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
import luno
from requests.auth import HTTPBasicAuth

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
EXCHANGE_RATE_API_URL = os.getenv("EXCHANGE_RATE_API_URL", "https://api.exchangerate-api.com/v4/latest/ZAR")
LUNO_API_KEY_ID = os.getenv("LUNO_API_KEY_ID")
LUNO_API_SECRET = os.getenv("LUNO_API_SECRET")
COINGECKO_API_URL = os.getenv("COINGECKO_API_URL", "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=zar")
COINGECKO_XLM_URL = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=zar"
COINGECKO_BTC_URL = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=zar"


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
    crypto_amount = db.Column(db.Float, nullable=True)  # Amount converted to USDT/XLM
    final_amount = db.Column(db.Float, nullable=True)  # Final payout in target currency
    currency = db.Column(db.String(10), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # Deposit, Withdrawal, Transfer
    status = db.Column(db.String(20), default="Pending")
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    converted_amount = db.Column(db.Float, nullable=True) 

# ========= FORMS =========
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

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

def get_best_crypto_rate():
    try:
        urls = [COINGECKO_XLM_URL, COINGECKO_BTC_URL]
        rates = []

        for url in urls:
            response = requests.get(url).json()

            if "stellar" in response and "zar" in response["stellar"]:
                rates.append(float(response["stellar"]["zar"]))
            if "bitcoin" in response and "zar" in response["bitcoin"]:
                rates.append(float(response["bitcoin"]["zar"]))

        return {"best_user_rate": min(rates), "best_sell_rate": max(rates)} if rates else None
    except Exception as e:
        logging.error(f"Error fetching Stellar/Bitcoin prices: {e}")
        return None

def get_luno_crypto_rate():
    """
    Fetches the latest crypto rate from Luno for ZAR/USDT.
    """
    try:
        response = requests.get(
            "https://api.luno.com/api/1/ticker?pair=USDTZAR",  # ✅ Corrected Market Pair
            auth=HTTPBasicAuth(LUNO_API_KEY_ID, LUNO_API_SECRET)
        ).json()

        if "last_trade" in response:
            return float(response["last_trade"])  # ✅ Returns latest USDT/ZAR rate
        else:
            logging.error("Luno API response did not contain last trade price.")
            return None
    except Exception as e:
        logging.error(f"Error fetching Luno exchange rate: {e}")
        return None

def get_live_exchange_rates():
    try:
        response = requests.get(EXCHANGE_RATE_API_URL)
        response.raise_for_status()  # Raises an error if the request fails
        rates = response.json().get("rates", {})

        if not rates:
            logging.error("Exchange rate API returned empty rates!")
            return {}

        return rates
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching exchange rates: {e}")
        return {}

def convert_zar_to_crypto(amount_zar):
    rates = get_live_exchange_rates()
    luno_rate = get_luno_crypto_rate()
    stellar_rate_data = get_best_crypto_rate()

    if stellar_rate_data:
        stellar_rate = stellar_rate_data["best_user_rate"]
    else:
        stellar_rate = None

    # Select best available rate
    zar_to_crypto_rate = min(filter(None, [luno_rate, stellar_rate]))

    if zar_to_crypto_rate:
        amount_after_fee = amount_zar * 0.90  # ✅ Deduct 10% user fee
        crypto_amount = amount_after_fee / zar_to_crypto_rate
        return round(crypto_amount, 2)

    return 0  # If no rates available

def send_payout_to_customer(bank_account, amount, currency):
    try:
        print(f"✅ Sending {amount} {currency} to {bank_account}")
        return True  # Simulating success (Replace with Binance/Stellar API)
    except Exception as e:
        logging.error(f"Error sending payout: {e}")
        return False

scheduler = BackgroundScheduler()
def update_rates():
    try:
        luno_rate = get_luno_crypto_rate()  # ✅ Fetch the latest Luno rate
        if luno_rate:
            print(f"✅ Updated Luno Rate: {luno_rate} ZAR/USDT")
        else:
            print("⚠️ Failed to fetch Luno rate.")

    except Exception as e:
        logging.error(f"Error updating rates: {e}")

scheduler.add_job(update_rates, 'interval', minutes=1)  # ✅ Runs every 1 minute
scheduler.start()

def convert_zar_to_usdt(amount_zar):
    zar_btc_rate = get_luno_exchange_rate()
    if not zar_btc_rate:
        return 0

    btc_amount = amount_zar / zar_btc_rate  # Convert ZAR to BTC

    try:
        response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usdt").json()
        btc_usdt_rate = float(response["bitcoin"]["usdt"])
    except Exception as e:
        logging.error(f"Error fetching BTC to USDT rate: {e}")
        return 0

    return round(btc_amount * btc_usdt_rate, 2)

def convert_crypto_to_fiat(crypto_amount, target_currency):
    rates = get_live_exchange_rates()
    rate = rates.get(target_currency, 1)  # Default fallback rate
    final_amount = crypto_amount * rate * 0.98  # Apply 2% spread for profit
    return round(final_amount, 2)


@app.route('/')
def home():
    return render_template("index.html") 

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Use the new form
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
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

    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Initialize the form instance
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(Username=username).first()

        if user and user.check_password(password):
            session['user_ID'] = user.ID
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")

    return render_template("login.html", form=form)

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

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_ID' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    form = EditProfileForm()  

    if request.method == 'POST':
        if 'email' in request.form and 'full_name' in request.form:
            user.email = request.form['email']
            user.full_name = request.form['full_name']
            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('dashboard'))

    return render_template("edit_profile.html", user=user, form=form)


@app.route('/add_beneficiary', methods=['GET', 'POST'])
def add_beneficiary():
    if 'user_ID' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))
    form = AddBeneficiaryForm()  # ✅ Initialize the form

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

    return render_template("add_beneficiary.html", form=form)

# ✅ Define this function at the top of your app.py before using it
def convert_crypto_to_fiat(crypto_amount, target_currency):
    rates = get_live_exchange_rates()
    rate = rates.get(target_currency, 1)  # Default fallback rate
    final_amount = crypto_amount * rate * 0.98  # Apply 2% spread for profit
    return round(final_amount, 2)

@app.route('/send_money', methods=['GET', 'POST'])
def send_money():
    if 'user_ID' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))  

    user = User.query.get(session['user_ID'])
    beneficiaries = Beneficiary.query.filter_by(user_id=user.ID).all()

    form = SendMoneyForm()
    form.beneficiary_id.choices = [(b.id, f"{b.name} - {b.bank_account}") for b in beneficiaries]

    if request.method == 'POST' and form.validate_on_submit():
        try:
            amount_zar = float(form.amount.data)
            beneficiary_id = int(form.beneficiary_id.data)
            beneficiary = Beneficiary.query.get(beneficiary_id)

            if not beneficiary:
                flash("Invalid beneficiary selected!", "danger")
                return redirect(url_for('send_money'))

            if user.balance < amount_zar:
                flash("❌ Insufficient balance!", "danger")
                return redirect(url_for('send_money'))

            currency = beneficiary.currency  # Get beneficiary's currency

            # Deduct 10% fee from the amount
            amount_after_fee = round(amount_zar * 0.90, 2)

            # Convert ZAR directly to the target currency
            live_rates = get_live_exchange_rates()
            payout_rate = live_rates.get(currency, 0)

            if payout_rate == 0:
                flash("⚠ Exchange rate unavailable. Please try again later.", "danger")
                return redirect(url_for('send_money'))

            final_payout = round(amount_after_fee * payout_rate, 2)

            print(f"✅ Sending {final_payout} {currency} to {beneficiary.name}")

            # Simulate Payout (Replace this with actual API call)
            payout_success = send_payout_to_customer(beneficiary.bank_account, final_payout, currency)

            if payout_success:
                # Deduct balance from user
                user.balance -= amount_zar

                # Save Transaction in Database
                transaction = Transaction(
                    user_id=user.ID,
                    beneficiary_id=beneficiary_id,
                    amount=amount_zar,
                    amount_after_fees=amount_after_fee,  # ✅ Store amount after fees
                    final_amount=final_payout,  # ✅ Store final payout amount
                    currency=currency,
                    transaction_type="Transfer",
                    status="Success"
                )
                db.session.add(transaction)
                db.session.commit()

                print("✅ Transaction added to database!")
                flash(f"Successfully sent {final_payout} {currency} to {beneficiary.name}!", "success")
                return redirect(url_for('dashboard'))  # Redirect to dashboard

            else:
                flash("❌ Transaction failed. Please try again.", "danger")

        except Exception as e:
            print(f"❌ Error processing transaction: {e}")
            flash("⚠ An error occurred. Please try again later.", "danger")

    return render_template("send_money.html", form=form, user=user, beneficiaries=beneficiaries)


@app.route('/dashboard')
def dashboard():
    if 'user_ID' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_ID'])
    transactions = Transaction.query.filter_by(user_id=user.ID).order_by(Transaction.timestamp.desc()).all()
    beneficiaries = Beneficiary.query.filter_by(user_id=user.ID).all()
    # Fetch the latest exchange rate
    latest_rate = get_luno_crypto_rate()  # Make sure this returns a valid number

    # Calculate user’s balance in USDT after fees
    zar_balance = user.balance  # Get user's ZAR balance
    balance_after_fee = zar_balance * 0.90  # Deduct 10% fee
    converted_usdt = round(balance_after_fee / latest_rate, 2) if latest_rate else 0

    print(f"🔹 Transactions for {user.Username}: {transactions}")
    
    # ✅ Add an empty form (for CSRF protection if needed)
    form = SendMoneyForm()  

    return render_template("dashboard.html", user=user, transactions=transactions, exchange_rate=latest_rate, converted_usdt=converted_usdt, fees=zar_balance - balance_after_fee, beneficiaries=beneficiaries, form=form)

@app.route('/get_conversion_preview')
def get_conversion_preview():
    try:
        amount_zar = float(request.args.get('amount', 0))
        beneficiary_currency = request.args.get('currency', 'USD')  # Default to USD if not specified

        if amount_zar <= 0:
            return jsonify({"error": "Invalid amount"}), 400

        # Deduct 10% fee
        amount_after_fee = amount_zar * 0.90  

        # Get live exchange rates (ZAR to target currency)
        live_rates = get_live_exchange_rates()
        payout_rate = live_rates.get(beneficiary_currency, 0)

        if payout_rate == 0:
            return jsonify({"error": "Exchange rate unavailable"}), 500

        # Convert directly to beneficiary currency
        final_payout = round(amount_after_fee * payout_rate, 2)

        return jsonify({
            "amount_entered": round(amount_zar, 2),
            "amount_after_fees": round(amount_after_fee, 2),
            "payout_currency": beneficiary_currency,
            "final_payout": final_payout
        })

    except Exception as e:
        logging.error(f"Error in conversion preview: {e}")
        return jsonify({"error": "Server error"}), 500


@app.route('/get_exchange_rate', methods=['GET'])
def get_exchange_rate():
    amount = request.args.get('amount', type=float)
    currency = request.args.get('currency')

    if not amount or not currency:
        return jsonify({"error": "Missing amount or currency"}), 400

    rates = get_live_exchange_rates()
    exchange_rate = rates.get(currency)

    if not exchange_rate:
        return jsonify({"error": f"Currency {currency} not supported"}), 400

    # Apply Upfront Fee (10% deduction before conversion)
    amount_after_fee = amount * 0.90  

    # Convert ZAR to Target Currency
    converted_amount = amount_after_fee * exchange_rate

    # Apply Spread Fee (2% deduction after conversion)
    final_amount = round(converted_amount * 0.98, 2)

    return jsonify({
        "exchange_rate": round(exchange_rate, 6),
        "converted_amount": round(converted_amount, 2),
        "final_amount_after_fees": final_amount
    })

@app.route('/get_live_rates', methods=['GET'])
def get_live_rates():
    try:
        rates = get_live_exchange_rates()  # Fetch from API
        best_rate = rates.get("USD", 0)  # Default to USD
        return jsonify({
            "exchange_rate": round(best_rate, 2),
            "selected_currency": "USD"
        })
    except Exception as e:
        logging.error(f"Error fetching live rates: {e}")
        return jsonify({"error": "Failed to fetch rates"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500

@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://apis.google.com;"
    return response


if __name__ == "__main__":
    import threading
    threading.Thread(target=background_deposit_checker, daemon=True).start()

    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

    # Ensure port is correctly handled
    port = os.getenv("PORT", "8000")  # Get PORT as a string, default to "8000"
    if not port.isdigit():  
        port = "8000"  # Default to "8000" if invalid

    app.run(host="0.0.0.0", port=int(port), debug=False)