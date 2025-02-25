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

# ====== CONFIGURATION ======
STELLAR_SECRET = os.getenv("STELLAR_SECRET_KEY")
STELLAR_PUBLIC = os.getenv("STELLAR_PUBLIC_KEY")
HORIZON_SERVER = Server(os.getenv("HORIZON_SERVER", "https://horizon.stellar.org"))
# Updated fee & markup percentages
UPFRONT_FEE_PERCENTAGE = 0.10   # 10% upfront fee
SPREAD_PERCENTAGE = 0.0263      # ~2.63% markup (to simulate buying at ZAR19 and selling at ZAR19.50)
BINANCE_API_URL = "https://api.binance.com/api/v3/ticker/price?symbol=USDZAR"
COINGECKO_XLM_URL = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usd"
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
LUNO_API_URL = "https://api.luno.com/api/v3/ticker?pair=ZAR_USDT"
EMAIL_HOST = "imap.gmail.com"
EMAIL_USER = os.getenv("EMAIL_USER", "your-email@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "your-email-password")

# MoMo & Mpesa Credentials
MOMO_API_KEY = os.getenv("MOMO_API_KEY", "your_momo_api_key")
MOMO_SUBSCRIPTION_KEY = os.getenv("MOMO_SUBSCRIPTION_KEY", "your_momo_subscription_key")
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY", "your_mpesa_consumer_key")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET", "your_mpesa_consumer_secret")


# Configuration
SPREAD_PERCENTAGE = 0.0263  # 2.63% spread markup
CURRENCY_APIS = {
    "USD": "https://api.exchangerate-api.com/v4/latest/ZAR",
    "EUR": "https://api.exchangerate-api.com/v4/latest/ZAR",
    "GBP": "https://api.exchangerate-api.com/v4/latest/ZAR",
    "CNY": "https://api.exchangerate-api.com/v4/latest/ZAR",
    "BWP": "https://api.exchangerate-api.com/v4/latest/ZAR",
    "ZAR": "https://api.exchangerate-api.com/v4/latest/USD"
}

# Add in your environment variables
EXCHANGERATE_API_KEY = os.getenv("EXCHANGERATE_API_KEY")

# ========= MODELS =========
class User(db.Model):
    __tablename__ = 'Users'
    ID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # new field
    full_name = db.Column(db.String(120), nullable=True)           # new field
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    id_number = db.Column(db.String(50), nullable=True)  # new field
    country = db.Column(db.String(50), nullable=False)
    bank_name = db.Column(db.String(100), nullable=True)
    bank_account = db.Column(db.String(50), nullable=True)
    mobile_wallet = db.Column(db.String(50), nullable=True)
    blockchain_address = db.Column(db.String(255), nullable=True)
    currency = db.Column(db.String(10), nullable=False)
    company_name = db.Column(db.String(100), nullable=True)
    company_reg_number = db.Column(db.String(50), nullable=True)

class Transaction(db.Model):
    __tablename__ = 'Transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
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

class SendMoneyForm(FlaskForm):
    csrf_token = HiddenField()
    name = StringField('Your Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    amount = DecimalField('Amount in ZAR', validators=[DataRequired()])
    beneficiary_id = SelectField('Select Beneficiary', coerce=int)
    recipient = StringField("Recipient")
    payout_method = SelectField('Payout Method', choices=[('Bank', 'Bank Transfer'), ('Mobile Money', 'Mobile Money'), ('blockchain', 'Crypto Wallet')])
    submit = SubmitField('Send Money Instantly')

class EditProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Update Profile")

class DepositForm(FlaskForm):
    amount = DecimalField("Deposit Amount", validators=[DataRequired()])
    submit = SubmitField("Deposit")

class AddBeneficiaryForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    blockchain_address = StringField('Blockchain Wallet Address')
    submit = SubmitField('Add Beneficiary')

# Simulated Database for demonstration (in production, use actual DB queries)
user_balances = {}  # User Wallets
user_accounts = {"user1": "ITRADE-ABC12345"}  # User Account Numbers
user_emails = {"user1": "user1@example.com"}  # User Emails

# ========= HELPER FUNCTIONS =========
def generate_account_number():
    """Generates a unique iTradeAfrika account number."""
    return f"ITRADE-{uuid.uuid4().hex[:8]}"

# Example usage
user_account_number = generate_account_number()
print(f"User Account Number: {user_account_number}")

def check_email_for_deposits():
    try:
        mail = imaplib.IMAP4_SSL(EMAIL_HOST)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")
        _, messages = mail.search(None, "UNSEEN")
        for msg_num in messages[0].split():
            _, msg_data = mail.fetch(msg_num, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = msg["subject"]
                    body = msg.get_payload(decode=True).decode()
                    # Extract deposit amount & reference number from email
                    match = re.search(r"Deposit of R(\d+)\s+Ref: (ITRADE-\w+)", body)
                    if match:
                        amount = int(match.group(1))
                        reference = match.group(2)
                        # Allocate funds if reference exists
                        for user_id, account_number in user_accounts.items():
                            if reference == account_number:
                                user_balances[user_id] = user_balances.get(user_id, 0) + amount
                                print(f"✅ Deposit of R{amount} allocated to {user_id}!")
                                send_in_app_notification(user_id, f"R{amount} has been credited to your wallet.")
                                send_email_notification(user_emails[user_id], f"Your deposit of R{amount} has been processed.")
        mail.logout()
    except Exception as e:
        print(f"❌ Error checking email: {e}")

def send_in_app_notification(user_id, message):
    print(f"📱 In-App Notification to {user_id}: {message}")

def send_email_notification(email_addr, message):
    print(f"📧 Email sent to {email_addr}: {message}")

def get_binance_rate():
    try:
        response = requests.get(BINANCE_API_URL).json()
        return float(response.get("price", 18.5))
    except Exception as e:
        print("Error fetching Binance rate:", e)
        return 18.5

def get_xlm_price():
    # Using CoinGecko for XLM/USDT price as fallback
    url = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usdt"
    try:
        data = requests.get(url, timeout=5).json()
        return float(data.get("stellar", {}).get("usdt", 0.345))
    except Exception as e:
        print(f"Error fetching XLM price: {e}")
        return 0.345

def get_luno_exchange_rate():
    # Using Luno API endpoint for ZAR/USDC (update URL if needed)
    url = "https://api.luno.com/v1/ticker?pair=ZARUSDC"
    try:
        response = requests.get(url, auth=(os.getenv("LUNO_API_KEY"), os.getenv("LUNO_API_SECRET")))
        data = response.json()
        return float(data.get("last_trade", 18.5))
    except Exception as e:
        print(f"Error fetching Luno rate: {e}")
        return 18.5  # Fallback

def get_coingecko_zar_usdt_rate():
    url = "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=zar"
    response = requests.get(url)
    if response.status_code == 200:
        return float(response.json()["tether"]["zar"])
    return 18.35

def convert_zar_to_xlm(amount_zar):
    """Converts ZAR to USDT then USDT to XLM while applying fees and markup."""
    amount_after_fee = amount_zar * (1 - UPFRONT_FEE_PERCENTAGE)
    zar_to_usdt = get_coingecko_zar_usdt_rate()
    xlm_to_usdt = get_xlm_price()
    effective_rate = zar_to_usdt * (1 - SPREAD_PERCENTAGE)
    usdt_amount = amount_after_fee / effective_rate
    xlm_amount = usdt_amount / xlm_to_usdt
    return round(xlm_amount, 2)

def apply_transaction_fee(amount, method):
    TRANSACTION_FEES = {
        "bank": 0.02,       # 2%
        "mobile money": 0.015,  # 1.5%
        "blockchain": 0.01  # 1%
    }
    fee_percentage = TRANSACTION_FEES.get(method, 0)
    fee_deduction = amount * fee_percentage
    # Optionally add a flat fee for mobile money
    if method == "mobile money":
        fee_deduction += 5
    return max(amount - fee_deduction, 0)

def convert_zar_to_usdt(amount_zar):
    """Converts ZAR to USDT using Luno rate (assumes 1 USDT = 1 USD)."""
    zar_to_usdt = get_luno_exchange_rate()
    return round(amount_zar / zar_to_usdt, 2) if zar_to_usdt else 0

def convert_usdt_to_xlm(amount_usdt):
    xlm_price = get_xlm_price()
    return round(amount_usdt / xlm_price, 2)

def send_stellar_payment(destination, amount, asset="XLM"):
    """Enhanced with African market requirements"""
    try:
        keypair = Keypair.from_secret(STELLAR_SECRET)
        server = Server("https://horizon.stellar.org")
        
        # Check if destination account exists
        try:
            server.load_account(destination)
        except:
            # Create account for unbanked users
            friendbot = requests.get(f"https://friendbot.stellar.org?addr={destination}")
            
        # Build transaction
        account = server.load_account(keypair.public_key)
        fee = server.fetch_base_fee() * 2  # Priority fee
        
        transaction = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
                base_fee=fee
            )
            .append_payment_op(
                destination=destination,
                asset=Asset.native() if asset == "XLM" else Asset(asset, os.getenv("ASSET_ISSUER")),
                amount=str(amount)
            )
            .add_text_memo("iTradeAfrika Remittance")
            .set_timeout(30)
            .build()
        )
        
        transaction.sign(keypair)
        return server.submit_transaction(transaction)
    except Exception as e:
        logging.error(f"Stellar Error: {str(e)}")
        return None

def send_momo_payment(phone_number, amount, currency="ZAR"):
    url = "https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay"
    headers = {
        "Authorization": f"Bearer {MOMO_API_KEY}",
        "X-Target-Environment": "sandbox",
        "Ocp-Apim-Subscription-Key": MOMO_SUBSCRIPTION_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "amount": str(amount),
        "currency": currency,
        "externalId": "123456",
        "payer": {"partyIdType": "MSISDN", "partyId": phone_number},
        "payerMessage": "iTradeAfrika Transfer",
        "payeeNote": "Thank you for using iTradeAfrika!"
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()

def get_mpesa_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    headers = {
        "Authorization": "Basic " + base64.b64encode(
            f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}".encode()).decode()
    }
    response = requests.get(url, headers=headers)
    return response.json().get("access_token")

def send_mpesa_money(phone_number, amount, currency="KES"):
    token = get_mpesa_token()
    url = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "InitiatorName": "TestAPI",
        "SecurityCredential": "YOUR_SECURITY_CREDENTIAL",
        "CommandID": "BusinessPayment",
        "Amount": amount,
        "PartyA": "YOUR_SHORTCODE",
        "PartyB": phone_number,
        "Remarks": "iTradeAfrika Transfer",
        "QueueTimeOutURL": "https://yourdomain.com/mpesa/timeout",
        "ResultURL": "https://yourdomain.com/mpesa/result"
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()

def apply_transaction_fee(amount, method, settlement="standard"):
    """
    Applies transaction fees based on the method:
      - Bank Transfers: 1% fee + R10
      - Mobile Money: 1.5% fee + R15
      - Blockchain: standard settlement 1%, instant settlement 2%
    Deducts fee from the converted amount.
    """
    fee = 0
    if method == "bank":
        fee += amount * 0.01 + 10
    elif method == "momo":
        fee += amount * 0.015 + 15
    elif method == "blockchain":
        fee += amount * (0.02 if settlement == "instant" else 0.01)
    return round(amount - fee, 2)

def get_live_exchange_rate():
    """Fetch live exchange rates for ZAR to USDT and XLM to USDT using CoinGecko and Luno."""
    try:
        # ZAR to USDT rate from Luno
        zar_usdt = get_luno_exchange_rate()
    except Exception:
        zar_usdt = 18.5
    try:
        # XLM/USDT rate from CoinGecko
        xlm_usdt = get_xlm_price()
    except Exception:
        xlm_usdt = 0.345
    return {"zar_usdt": zar_usdt, "xlm_usdt": xlm_usdt}

# Background deposit checker task
def background_deposit_checker():
    while True:
        check_email_for_deposits()
        time.sleep(30)

def get_exchange_rate(from_currency, to_currency):
    url = f"https://api.exchangerate-api.com/v4/latest/{from_currency}"
    response = requests.get(url).json()
    return response["rates"].get(to_currency, 1)

# Function to fetch live exchange rates
def get_currency_rate(target_currency):
    try:
        url = f"https://v6.exchangerate-api.com/v6/{EXCHANGERATE_API_KEY}/pair/ZAR/{target_currency}"
        response = requests.get(url).json()
        rate = response.get('conversion_rate')
        if rate:
            return rate * (1 - SPREAD_PERCENTAGE)  # Apply spread
        return None
    except Exception as e:
        print(f"Error fetching {target_currency} rate: {e}")
        return None

# Function to convert ZAR to target currency
def convert_zar_to_currency(amount_zar, target_currency):
    rate = get_currency_rate(target_currency)
    if rate:
        converted = amount_zar * rate  # Convert using multiplication
        return round(converted - (converted * UPFRONT_FEE_PERCENTAGE), 2)  # Apply fee
    return None

# Example usage
if __name__ == "__main__":
    zar_amount = 1000  # Example ZAR amount
    print(f"ZAR to EUR: {convert_zar_to_currency(zar_amount, 'EUR')} EUR")
    print(f"ZAR to GBP: {convert_zar_to_currency(zar_amount, 'GBP')} GBP")
    print(f"ZAR to CNY: {convert_zar_to_currency(zar_amount, 'CNY')} CNY")
    print(f"ZAR to BWP: {convert_zar_to_currency(zar_amount, 'BWP')} BWP")

def update_rates():
    with app.app_context():
        # Update all cached exchange rates
        pass

scheduler = BackgroundScheduler()
scheduler.add_job(func=update_rates, trigger="interval", hours=1)
scheduler.start()

# ========= ROUTES =========
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("User already exists!")
            return redirect(url_for('register'))
        unique_account_number = f"ITRADE-{User.query.count() + 1000}"
        new_user = User(username=username, account_number=unique_account_number)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        flash("Registration successful. You can now log in.")
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(Username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_ID'] = user.ID
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route('/dashboard')
def dashboard():
    if 'user_ID' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_ID'])
    exchange_rate = get_live_exchange_rate()
    converted_amount = round(user.balance / exchange_rate['zar_usdt'], 2) if user.balance else None
    beneficiaries = Beneficiary.query.filter_by(user_id=user.ID).all()
    return render_template('dashboard.html', user=user, exchange_rate=exchange_rate, converted_amount=converted_amount, beneficiaries=beneficiaries)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    form = DepositForm()
    if form.validate_on_submit():
        amount = form.amount.data
        flash(f"Successfully deposited {amount}!", "success")
        return redirect(url_for("deposit"))
    if 'user_id' not in session:
        return redirect(url_for('deposit'))
    user = User.query.get(session['user_ID'])
    if request.method == 'POST':
        amount = float(request.form['amount'])
        user.Balance += amount
        db.session.commit()
        flash(f"Deposited ZAR {amount:.2f}")
        return redirect(url_for('dashboard'))
    return render_template('deposit.html', user=user, form=form)

@app.route('/check-deposits', methods=['GET'])
def manual_check():
    check_email_for_deposits()
    return jsonify({"message": "Deposit check completed."})

@app.route("/confirm-deposit", methods=["GET", "POST"])
def confirm_deposit():
    if 'user_ID' not in session:
        return redirect(url_for("login"))
    user = User.query.get(session['user_ID'])
    if request.method == "POST":
        amount = float(request.form["amount"])
        txn = Transaction(
            user_ID=user.ID,
            amount=amount,
            status="Pending",
            timestamp=datetime.utcnow(),
            currency="ZAR",
            transaction_type="Deposit"
        )
        db.session.add(txn)
        db.session.commit()
        flash("Deposit request submitted. Admin will verify and approve.", "success")
        return redirect(url_for("dashboard"))
    return render_template("confirm_deposit.html", user=user)

@app.route("/admin/deposits")
def admin_deposits():
    deposits = Transaction.query.filter_by(status="Pending").all()
    return render_template("admin_deposits.html", deposits=deposits)

@app.route("/admin/approve/<int:txn_id>")
def approve_deposit(txn_id):
    txn = Transaction.query.get(txn_id)
    if txn and txn.status == "Pending":
        txn.status = "Deposited"
        user = User.query.get(txn.user_ID)
        fee_percentage = 10  # Example fee percentage
        user.balance += txn.amount * ((100 - fee_percentage) / 100)
        db.session.commit()
        flash(f"Deposit of {txn.amount} approved.", "success")
    return redirect(url_for("admin_deposits"))

@app.route('/add_beneficiary', methods=['GET', 'POST'])
def add_beneficiary():
    if 'user_ID' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_ID'])
    if not user:
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('login'))
    form = AddBeneficiaryForm()
    if form.validate_on_submit():
        try:
            new_beneficiary = Beneficiary(
                user_ID=user.ID,
                name=form.full_name.data,
                id_number=form.id_number.data,
                country=form.country.data,
                bank_name=form.bank_name.data,
                bank_account=form.account_number.data,
                mobile_wallet=form.phone_number.data,
                blockchain_address=form.blockchain_address.data
            )
            db.session.add(new_beneficiary)
            db.session.commit()
            flash("Beneficiary added successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding beneficiary: {str(e)}", "danger")
            return redirect(url_for("add_beneficiary"))
    beneficiaries = Beneficiary.query.filter_by(user_id=user.ID).all()
    return render_template('add_beneficiary.html', user=user, beneficiaries=beneficiaries, form=form)

@app.route("/get_exchange_rate", methods=["GET"])
def get_exchange_rate():
    method = request.args.get("method")
    amount = request.args.get("amount")
    if not method or not amount:
        return jsonify({"error": "Missing parameters"}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({"error": "Amount must be greater than zero"}), 400
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400
    try:
        usd_zar_rate = get_luno_exchange_rate() or 18.5
    except Exception:
        usd_zar_rate = 18.5
    try:
        usdt_xlm_rate = get_xlm_price() or 0.345
    except Exception:
        usdt_xlm_rate = 0.345
    # Define exchange rates for different payout methods
    exchange_rates = {
        "bank": usd_zar_rate,
        "momo": usd_zar_rate * 0.975,
        "blockchain": (1 / usdt_xlm_rate) * usd_zar_rate
    }
    rate = exchange_rates.get(method.lower())
    if rate is None:
        return jsonify({"error": "Invalid method"}), 400
    # For our calculation, we assume that the converted amount is:
    converted_amount = amount / rate
    return jsonify({
        "method": method,
        "amount": amount,
        "exchange_rate": round(rate, 4),
        "converted_amount": round(converted_amount, 2)
    })

@app.route("/send_money", methods=["GET", "POST"])
@login_required
def send_money():
    user = User.query.get(session['user_ID'])
    beneficiaries = Beneficiary.query.filter_by(user_id=user.ID).all()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        currency = request.form['currency']
        beneficiary_id = request.form['beneficiary']
        payment_method = request.form['payment_method']
        
        # Get conversion rate
        rate = get_currency_rate(currency)
        if not rate:
            flash("Could not fetch exchange rate", "danger")
            return redirect(url_for('send_money'))
            
        # Calculate final amount with fees
        converted_amount = amount * rate
        final_amount = apply_transaction_fee(converted_amount, payment_method)
        
        # Process payment
        beneficiary = Beneficiary.query.get(beneficiary_id)
        if payment_method == 'bank':
            process_bank_transfer(beneficiary.bank_account, final_amount)
        elif payment_method == 'momo':
            process_mobile_money(beneficiary.phone, final_amount)
        
        flash(f"Successfully sent {final_amount} {currency}!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template("send_money.html", user=user, beneficiaries=beneficiaries)

# ---- Payment Processing Functions ----
def process_bank_transfer(account, amount):
    print(f"Bank transfer of {amount} USD to {account}")
    return f"Bank transfer of {amount} USD to {account} initiated"

def process_mobile_money_transfer(phone, amount):
    print(f"Mobile Money transfer of {amount} USD to {phone}")
    return f"Mobile Money transfer of {amount} USD to {phone} initiated"

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_ID' not in session:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_ID'])
    form = EditProfileForm(obj=user)
    if form.validate_on_submit():
        user.full_name = form.name.data
        user.email = form.email.data
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))
    return render_template('edit_profile.html', user=user, form=form)

# ---- Additional Conversion Routes (USDC/USDT) ----
@app.route("/convert_zar_to_usdc", methods=["POST"])
def convert_zar_to_usdc():
    data = request.json
    zar_amount = float(data["amount"])
    zar_to_xlm_rate = get_luno_rate()
    if zar_to_xlm_rate == 0:
        return jsonify({"error": "Failed to fetch Luno rate"}), 400
    xlm_amount = zar_amount / zar_to_xlm_rate
    source_keypair = Keypair.from_secret(STELLAR_SECRET)
    source_account = HORIZON_SERVER.load_account(source_keypair.public_key)
    transaction = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100
        )
        .append_path_payment_strict_receive_op(
            destination=source_keypair.public_key,
            send_asset=Asset.native(),
            send_max=str(xlm_amount),
            dest_asset=STELLAR_ASSET_USDC,
            dest_amount="1"
        )
        .set_timeout(30)
        .build()
    )
    transaction.sign(source_keypair)
    response = HORIZON_SERVER.submit_transaction(transaction)
    if response.get("successful", False):
        usdc_received = float(response.get("amount", 0))
        return jsonify({"usdc_received": usdc_received, "message": "ZAR converted to USDC successfully."})
    else:
        return jsonify({"error": "Conversion failed"}), 400

@app.route("/sell_usdc_for_usd", methods=["POST"])
def sell_usdc_for_usd():
    data = request.json
    usdc_amount = float(data["usdc_amount"])
    source_keypair = Keypair.from_secret(STELLAR_SECRET)
    source_account = HORIZON_SERVER.load_account(source_keypair.public_key)
    transaction = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100
        )
        .append_path_payment_strict_receive_op(
            destination=source_keypair.public_key,
            send_asset=STELLAR_ASSET_USDC,
            send_max=str(usdc_amount),
            dest_asset=Asset("USD", os.getenv("USD_ISSUER", "DefaultUSDIssuer")),
            dest_amount="1"
        )
        .set_timeout(30)
        .build()
    )
    transaction.sign(source_keypair)
    response = HORIZON_SERVER.submit_transaction(transaction)
    if response.get("successful", False):
        usd_received = float(response.get("amount", 0))
        return jsonify({"usd_received": usd_received, "message": "USDC converted to USD successfully."})
    else:
        return jsonify({"error": "Conversion failed"}), 400

# ---- Process Transaction Route ----
@app.route("/process", methods=["POST"])
def process_transaction():
    try:
        data = request.json
        amount = float(data.get("amount", 0))
        beneficiary = data.get("beneficiary")
        method = data.get("method", "blockchain").lower()
        if not amount or amount <= 0 or not beneficiary:
            return jsonify({"status": "error", "message": "Invalid amount or beneficiary."}), 400
        # Get exchange rate (using our get_exchange_rate helper)
        exchange_response = get_exchange_rate().get_json()  # If your helper returns a response
        exchange_rate = exchange_response.get("exchange_rate", 18.5)
        final_amount = amount / exchange_rate
        final_amount = apply_transaction_fee(final_amount, method)
        # For this example, we’ll assume a simple process for payment
        if method == "blockchain":
            response = send_stellar_payment(beneficiary, str(final_amount), asset="XLM")
        elif method == "mobile money":
            response = send_momo_payment(beneficiary, final_amount)
        else:
            response = process_bank_transfer(beneficiary, final_amount)
        return jsonify({
            "status": "success",
            "method": method,
            "exchange_rate": round(exchange_rate, 4),
            "final_amount": round(final_amount, 2),
            "transaction_details": response
        })
    except Exception as e:
        logging.error(f"Error in processing transaction: {e}")
        return jsonify({"status": "error", "message": "Transaction failed. Please try again."}), 500

# ---- Bulk & B2B Transfers Route ----
@app.route('/bulk_transfer', methods=['POST'])
def bulk_transfer():
    """
    Processes bulk/B2B transfers.
    Expects JSON with a "transactions" list, each containing: amount, beneficiary, method, and optional settlement.
    """
    try:
        data = request.json
        transactions = data.get('transactions', [])
        results = []
        for txn in transactions:
            amount = float(txn.get('amount', 0))
            beneficiary = txn.get('beneficiary')
            method = txn.get('method', 'bank')
            settlement = txn.get('settlement', 'standard')
            if amount <= 0 or not beneficiary:
                results.append({'status': 'error', 'message': 'Invalid transaction data.'})
                continue
            usd_zar_rate = get_luno_rate() or 18.5
            xlm_usdt_rate = get_xlm_price() or 0.1
            exchange_rates = {
                "bank": usd_zar_rate,
                "momo": usd_zar_rate * 0.975,
                "blockchain": xlm_usdt_rate * usd_zar_rate
            }
            exchange_rate = exchange_rates.get(method)
            if not exchange_rate:
                results.append({'status': 'error', 'message': 'Invalid payment method.'})
                continue
            final_amount = amount / exchange_rate
            final_amount = apply_transaction_fee(final_amount, method, settlement)
            if method == "blockchain":
                response = send_stellar_payment(beneficiary, final_amount, asset="XLM")
            elif method == "momo":
                response = send_momo_payment(beneficiary, final_amount)
            else:
                response = process_bank_transfer(beneficiary, final_amount)
            results.append({
                'status': 'success',
                'final_amount': final_amount,
                'transaction_details': response
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Bulk transfer failed.'}), 500

if __name__ == "__main__":
    import threading
    threading.Thread(target=background_deposit_checker, daemon=True).start()
    db.create_all()
    print("Database tables created successfully!")
    app.run(debug=True)
