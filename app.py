from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import check_password_hash, generate_password_hash
from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from twilio.rest import Client as TwilioClient
from dotenv import load_dotenv
from flask_login import login_required
from apscheduler.schedulers.background import BackgroundScheduler
import os
import random
import string
from datetime import datetime
import requests
import time
import logging
import base64
import uuid
import imaplib
import email
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# External API Configuration
STELLAR_SECRET = os.getenv("STELLAR_SECRET_KEY")
STELLAR_PUBLIC = os.getenv("STELLAR_PUBLIC_KEY")
HORIZON_SERVER = Server(os.getenv("HORIZON_SERVER", "https://horizon.stellar.org"))
BINANCE_API_URL = "https://api.binance.com/api/v3/ticker/price?symbol=USDZAR"
EXCHANGERATE_API_KEY = os.getenv("EXCHANGERATE_API_KEY")
LUNO_API_KEY_ID = "mrzvz27595gqe"
LUNO_API_SECRET = os.getenv("LUNO_API_SECRET")

# ========= MODELS =========
class User(db.Model):
    __tablename__ = 'Users'
    ID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    full_name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column('Balance', db.Float, default=0.0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def generate_unique_account_number():
        while True:
            account_number = "ITRADE-" + ''.join(random.choices(string.digits, k=8))
            if not User.query.filter_by(account_number=account_number).first():
                return account_number

class Beneficiary(db.Model):
    __tablename__ = 'beneficiaries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.ID'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    id_number = db.Column(db.String(50), nullable=True)
    country = db.Column(db.String(50), nullable=False)
    bank_name = db.Column(db.String(100), nullable=True)
    bank_account = db.Column(db.String(50), nullable=True)
    currency = db.Column(db.String(10), nullable=False)

class Transaction(db.Model):
    __tablename__ = 'Transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.ID'), nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiaries.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # Deposit, Withdrawal, Transfer
    status = db.Column(db.String(20), default="Pending")
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# ========= FORMS =========
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class DepositForm(FlaskForm):
    amount = DecimalField("Deposit Amount", validators=[DataRequired()])
    submit = SubmitField("Deposit")

class SendMoneyForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    amount = DecimalField('Amount in ZAR', validators=[DataRequired()])
    beneficiary_id = SelectField('Select Beneficiary', coerce=int)
    submit = SubmitField('Send Money')

class EditProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Update Profile")

class AddBeneficiaryForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[("USD", "USD"), ("EUR", "EUR"), ("BWP", "BWP")])
    submit = SubmitField('Add Beneficiary')

def get_luno_crypto_rate():
    try:
        response = requests.get(
            "https://api.luno.com/api/1/ticker?pair=ZARUSDT",
            auth=(LUNO_API_KEY_ID, LUNO_API_SECRET)
        ).json()
        return float(response.get("last_trade", 0))
    except Exception as e:
        logging.error(f"Error fetching Luno rates: {e}")
        return None

# Convert ZAR to USDT using Luno
def convert_zar_to_crypto(amount_zar):
    zar_to_usdt_rate = get_luno_crypto_rate()
    if zar_to_usdt_rate:
        amount_after_fee = amount_zar * 0.90  # Deduct 10% fee
        return round(amount_after_fee / zar_to_usdt_rate, 2)
    return 0

def get_live_exchange_rates():
    try:
        response = requests.get(f"https://v6.exchangerate-api.com/v6/{EXCHANGERATE_API_KEY}/latest/ZAR")
        return response.json().get("conversion_rates", {})
    except Exception as e:
        logging.error(f"Error fetching exchange rates: {e}")
        return {}

def convert_zar_to_crypto(amount_zar):
    rates = get_live_exchange_rates()
    zar_to_usdt = rates.get("USDT", 18.5)  # Fallback rate
    amount_after_fee = amount_zar * 0.90  # Deduct 10% fee
    return round(amount_after_fee / zar_to_usdt, 2)

def convert_crypto_to_fiat(crypto_amount, target_currency):
    rates = get_live_exchange_rates()
    rate = rates.get(target_currency, 1)
    final_amount = crypto_amount * rate * 0.98  # Deduct 2% spread
    return round(final_amount, 2)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(Username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))

        new_user = User(
            Username=username,
            email=email,
            account_number=User.generate_unique_account_number()
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(Username=username).first()

        if user and user.check_password(password):
            session['user_ID'] = user.ID
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('user_ID', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/deposit', methods=['POST'])
def deposit():
    if 'user_ID' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    amount = float(request.form['amount'])

    if amount <= 0:
        flash("Invalid deposit amount!", "danger")
        return redirect(url_for('dashboard'))

    user.balance += amount
    db.session.commit()

    transaction = Transaction(
        user_id=user.ID,
        amount=amount,
        currency="ZAR",
        transaction_type="Deposit",
        status="Success"
    )
    db.session.add(transaction)
    db.session.commit()

    flash(f"Successfully deposited ZAR {amount:.2f}!", "success")
    return redirect(url_for('dashboard'))

@app.route('/add_beneficiary', methods=['GET', 'POST'])
def add_beneficiary():
    if 'user_ID' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        id_number = request.form['id_number']
        country = request.form['country']
        bank_name = request.form['bank_name']
        account_number = request.form['account_number']
        currency = request.form['currency']

        new_beneficiary = Beneficiary(
            user_id=user.ID,
            name=full_name,
            id_number=id_number,
            country=country,
            bank_name=bank_name,
            bank_account=account_number,
            currency=currency
        )

        db.session.add(new_beneficiary)
        db.session.commit()
        flash("Beneficiary added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template("add_beneficiary.html")

@app.route('/send_money', methods=['POST'])
def send_money():
    if 'user_ID' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    amount_zar = float(request.form['amount'])
    currency = request.form['currency']
    beneficiary_id = request.form['beneficiary_id']
    
    beneficiary = Beneficiary.query.get(beneficiary_id)
    if not beneficiary:
        flash("Invalid beneficiary!", "danger")
        return redirect(url_for('dashboard'))

    # Convert ZAR to USDT using Luno
    crypto_amount = convert_zar_to_crypto(amount_zar)
    if crypto_amount == 0:
        flash("Error fetching crypto rate. Try again.", "danger")
        return redirect(url_for('dashboard'))

    # Convert USDT to Fiat
    final_amount = convert_crypto_to_fiat(crypto_amount, currency)

    # Log transaction
    transaction = Transaction(
        user_id=user.ID,
        beneficiary_id=beneficiary_id,
        amount=final_amount,
        currency=currency,
        transaction_type="Transfer",
        status="Pending"
    )
    db.session.add(transaction)
    db.session.commit()

    flash(f"Successfully sent {final_amount:.2f} {currency} to {beneficiary.name}", "success")
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'user_ID' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    transactions = Transaction.query.filter_by(user_id=user.ID).order_by(Transaction.timestamp.desc()).all()
    
    return render_template("dashboard.html", user=user, transactions=transactions)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500



if __name__ == "__main__":
    import threading
    threading.Thread(target=background_deposit_checker, daemon=True).start()
    db.create_all()
    print("Database tables created successfully!")
    app.run(debug=True)
