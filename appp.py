from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import os
import random
import string
from datetime import datetime
import requests
from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from twilio.rest import Client
from dotenv import load_dotenv
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField, HiddenField 
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
import requests
import binance
import os
import base64
import uuid
import imaplib
import email
import re


# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = "29e2e2aef7ce5b0334d8221c8c935001ccfa2c0ccf87269ef4fd4359527f4801" 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# ====== CONFIGURATION ======
STELLAR_SECRET = os.getenv("STELLAR_SECRET_KEY")
STELLAR_PUBLIC = os.getenv("STELLAR_PUBLIC_KEY")
HORIZON_SERVER = Server(os.getenv("HORIZON_SERVER", "https://horizon.stellar.org"))
UPFRONT_FEE_PERCENTAGE = 0.10  # 10% upfront fee
SPREAD_PERCENTAGE = 0.02  # 2% profit spread
BINANCE_API_URL = "https://api.binance.com/api/v3/ticker/price?symbol=USDZAR"
COINGECKO_XLM_URL = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usd"
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
LUNO_API_KEY = "mrzvz27595gpe"
LUNO_API_SECRET = "wE4ILNMX-651hEGzjjLMKrXL1Ows14Uei0fK7oS6N14"
EMAIL_HOST = "imap.gmail.com"
EMAIL_USER = "your-email@gmail.com"
EMAIL_PASS = "your-email-password"


# MoMo & Mpesa Credentials
MOMO_API_KEY = "your_momo_api_key"
MOMO_SUBSCRIPTION_KEY = "your_momo_subscription_key"
MPESA_CONSUMER_KEY = "your_mpesa_consumer_key"
MPESA_CONSUMER_SECRET = "your_mpesa_consumer_secret"


# ========= Flask-WTF Login Form =========
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# ======= Database Models ========
class User(db.Model):
    __tablename__ = 'users'  # ✅ Use plural for consistency

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column(db.Float, default=0.0)

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
    __tablename__ = 'beneficiaries'  # ✅ Plural form

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ Corrected reference
    name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    bank_name = db.Column(db.String(100), nullable=True)
    bank_account = db.Column(db.String(50), nullable=True)
    mobile_wallet = db.Column(db.String(50), nullable=True)
    blockchain_address = db.Column(db.String(255), nullable=True)


class Transaction(db.Model):
    __tablename__ = 'transactions'  # ✅ Plural form

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ Corrected reference
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiaries.id'), nullable=True)  # ✅ Corrected reference
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # Deposit, Withdrawal, Transfer
    status = db.Column(db.String(20), default="Pending")
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class SendMoneyForm(FlaskForm):
    csrf_token = HiddenField()
    name = StringField('Your Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    amount = DecimalField('Amount in ZAR', validators=[DataRequired()])
    beneficiary_id = SelectField('Select Beneficiary', coerce=int)
    recipient = StringField("Recipient")
    payout_method = SelectField('Payout Method', choices=[('Bank', 'Bank Transfer'), ('Mobile Money', 'Mobile Money')])
    submit = SubmitField('Send Money Instantly')

class EditProfileForm(FlaskForm):
    name = StringField("Name")
    email = StringField("Email")
    submit = SubmitField("Update Profile")

class DepositForm(FlaskForm):
    amount = DecimalField("Deposit Amount", validators=[DataRequired()])
    submit = SubmitField("Deposit")

class AddBeneficiaryForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])  # ✅ Add this field
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Add Beneficiary')

# Simulated Database
user_balances = {}  # User Wallets
user_accounts = {"user1": "ITRADE-ABC12345"}  # User Account Numbers
user_emails = {"user1": "user1@example.com"}  # User Emails


# ======= Helper Functions ========
def generate_account_number():
    """Generates a unique iTradeAfrika account number."""
    return f"ITRADE-{uuid.uuid4().hex[:8]}"

# Example Usage
user_account_number = generate_account_number()
print(f"User Account Number: {user_account_number}")

# Function to check bank deposit emails
def check_email_for_deposits():
    try:
        mail = imaplib.IMAP4_SSL(EMAIL_HOST)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")

        _, messages = mail.search(None, "UNSEEN")  # Search for unread messages
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

                                # Send in-app & email notification
                                send_in_app_notification(user_id, f"R{amount} has been credited to your wallet.")
                                send_email_notification(user_emails[user_id], f"Your deposit of R{amount} has been processed.")

        mail.logout()

    except Exception as e:
        print(f"❌ Error checking email: {e}")

# Function to send in-app notification (Simulated)
def send_in_app_notification(user_id, message):
    print(f"📱 In-App Notification to {user_id}: {message}")

# Function to send email notification (Simulated)
def send_email_notification(email, message):
    print(f"📧 Email sent to {email}: {message}")

def get_binance_rate():
    """Fetches live USD/ZAR exchange rate from Binance."""
    try:
        response = requests.get(BINANCE_API_URL).json()
        return float(response.get("price", 18.5))  # Default fallback rate
    except Exception as e:
        print("Error fetching Binance rate:", e)
        return 18.5  # Fallback

def get_xlm_price():
    """Fetches XLM/USDT exchange rate from CoinGecko."""
    try:
        response = requests.get(COINGECKO_XLM_URL).json()
        return float(response.get("stellar", {}).get("usd", 0.1))  # Default 0.1 USDT if API fails
    except Exception as e:
        print("Error fetching XLM price:", e)
        return 0.1  # Fallback

def get_luno_rate():
    """Fetches live ZAR/USDT exchange rate from Luno."""
    try:
        response = requests.get(LUNO_API_URL).json()
        return float(response.get('last_trade', 18.5))  # Default fallback
    except Exception as e:
        print("Error fetching Luno rate:", e)
        return 18.5  # Fallback

def get_coingecko_zar_usdt_rate():
    """Fetches the ZAR/USDT rate from CoinGecko."""
    url = "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=zar"
    response = requests.get(url)
    if response.status_code == 200:
        return float(response.json()["tether"]["zar"])
    return 18.35  # Default fallback rate

def convert_zar_to_xlm(amount_zar):
    """Converts ZAR to USDT, then USDT to XLM while applying fees."""
    
    # Step 1: Deduct upfront fee (10%)
    amount_after_upfront_fee = amount_zar * (1 - UPFRONT_FEE)
    
    # Step 2: Get exchange rates
    zar_to_usdt = get_coingecko_zar_usdt_rate()
    xlm_to_usdt = get_binance_xlm_price()
    
    # Step 3: Apply the 2% spread to zar/usdt rate (to make a profit)
    zar_to_usdt_with_spread = zar_to_usdt * (1 - SPREAD)  # We give them slightly less USDT
    
    # Step 4: Convert ZAR → USDT
    usdt_amount = amount_after_upfront_fee / zar_to_usdt_with_spread
    
    # Step 5: Convert USDT → XLM
    xlm_amount = usdt_amount / xlm_to_usdt
    
    return round(xlm_amount, 2)

def apply_fees(amount_zar):
    """Applies a 10% upfront fee before conversion."""
    return round(amount_zar * (1 - UPFRONT_FEE_PERCENTAGE), 2)

def convert_zar_to_usdt(amount_zar):
    """Converts ZAR to USDT using Binance & Luno rates with a 2% spread."""
    zar_to_usdt = get_luno_rate()
    spread_adjusted_rate = zar_to_usdt * (1 - SPREAD_PERCENTAGE)  # Deduct 2% spread
    return round(amount_zar / spread_adjusted_rate, 2)

def convert_usdt_to_xlm(amount_usdt):
    """Converts USDT to XLM using CoinGecko rate."""
    xlm_price = get_xlm_price()
    return round(amount_usdt / xlm_price, 2)

def send_stellar_payment(destination, amount_xlm):
    """Sends XLM from your Stellar wallet to another Stellar address."""
    try:
        source_keypair = Keypair.from_secret(STELLAR_SECRET_KEY)
        source_account = STELLAR_SERVER.load_account(source_keypair.public_key)

        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
                base_fee=100
            )
            .add_text_memo("iTradeAfrika Payment")
            .add_operation(
                Payment(destination=destination, asset=Asset.native(), amount=str(amount_xlm))
            )
            .build()
        )

        transaction.sign(source_keypair)
        response = STELLAR_SERVER.submit_transaction(transaction)
        return response
    except Exception as e:
        print("Error processing Stellar transaction:", e)
        return {"error": str(e)}

def send_sms(to, message):
    """Sends an SMS notification using Twilio."""
    try:
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=message, from_=TWILIO_PHONE, to=to)
    except Exception as e:
        print("SMS send error:", e)

def send_momo_payment(phone_number, amount, currency="ZAR"):
    """Sends payment via MTN MoMo API."""
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
    """Fetches an access token for Mpesa API."""
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    headers = {
        "Authorization": "Basic " + base64.b64encode(
            f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}".encode()).decode()
    }
    response = requests.get(url, headers=headers)
    return response.json().get("access_token")

def send_mpesa_money(phone_number, amount, currency="KES"):
    """Sends money via Mpesa B2C API."""
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

def stellar_transfer(destination, amount, memo_text="iTradeAfrika Transfer"):
    """Transfers funds via Stellar with asset support."""
    source_keypair = Keypair.from_secret(STELLAR_SECRET_KEY)
    source_account = STELLAR_SERVER.load_account(source_keypair.public_key)
    usdc_asset = Asset("USDC", "GA5ZSEAR3K5XQ5UFWPPRNQ5BR6DFTBFU3F6ZZG5FV7Z5JRAHSWJID2D4")  # USDC asset issuer

    transaction = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100)
        .add_text_memo(memo_text)
        .append_payment_op(destination, amount, usdc_asset.code, usdc_asset.issuer)
        .build()
    )

    transaction.sign(source_keypair)
    response = STELLAR_SERVER.submit_transaction(transaction)

def process_transaction(amount_zar, payment_method, destination):
    """Handles the full transaction flow."""
    zar_after_fee = apply_fees(amount_zar)
    usdt_amount = convert_zar_to_usdt(zar_after_fee)
    xlm_amount = convert_usdt_to_xlm(usdt_amount)

    if payment_method == "blockchain":
        return send_stellar_payment(destination, xlm_amount)
    elif payment_method == "momo":
        return send_momo_payment(destination, zar_after_fee)
    elif payment_method == "mpesa":
        return send_mpesa_money(destination, zar_after_fee)
    else:
        return {"error": "Invalid payment method"}
    return response

# ======= Authentication Helpers ========
def login_required(func):
    from functools import wraps
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return decorated_view

# ======= Routes ========
@app.route("/")
def home():
    if "username" in session:  # Check if user is logged in
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
        new_user = User(username=username, password=password, account_number=unique_account_number)
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
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id  # ✅ Store user session
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # ✅ Redirect to Dashboard
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form) 

@app.route("/logout")
def logout():
    session.clear()  # Clears all session data
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Fetch live exchange rate
    exchange_rate = get_live_exchange_rate()
    converted_amount = None

    if user.balance:
        converted_amount = round(user.balance / exchange_rate['zar_usdt'], 2)  # Convert ZAR to USD

    beneficiaries = Beneficiary.query.filter_by(user_id=user.id).all()

    return render_template('dashboard.html', user=user, exchange_rate=exchange_rate, 
                           converted_amount=converted_amount, beneficiaries=beneficiaries)

def get_live_exchange_rate():
    """Fetch live exchange rates for ZAR to USDT and XLM to USDT."""
    try:
        # --- Get ZAR/USDT rate from CoinGecko ---
        coingecko_url = "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=zar"
        coingecko_response = requests.get(coingecko_url).json()
        zar_usdt = 1 / float(coingecko_response["tether"]["zar"])  # Convert ZAR to USDT

        # --- Get XLM/USDT rate from Binance ---
        binance_url = "https://api.binance.com/api/v3/ticker/price?symbol=XLMUSDT"
        binance_response = requests.get(binance_url).json()
        xlm_usdt = float(binance_response["price"])

        return {
            "zar_usdt": zar_usdt,
            "xlm_usdt": xlm_usdt
        }

    except Exception as e:
        print(f"⚠️ Error fetching exchange rates: {e}")
        return {
            "zar_usdt": 1 / 18.5,  # Default fallback rate
            "xlm_usdt": 0.345    # Default fallback price
        }

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    form = DepositForm()

    if form.validate_on_submit():
        amount = form.amount.data
        # Process deposit logic here...
        flash(f"Successfully deposited {amount}!", "success")
        return redirect(url_for("deposit"))  
    if 'user_id' not in session:
        return redirect(url_for('deposit'))  # Redirect to login if not authenticated
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        user.balance += amount  # Simulating deposit confirmation
        db.session.commit()
        flash(f"Deposited ZAR {amount:.2f}")
        return redirect(url_for('dashboard'))
    
    return render_template('deposit.html', user=user, form=form)

@app.route('/check-deposits', methods=['GET'])
def manual_check():
    check_email_for_deposits()
    return jsonify({"message": "Deposit check completed."})

# Background Task to Check Deposits Every 30 Seconds
def background_deposit_checker():
    while True:
        check_email_for_deposits()
        time.sleep(30)

@app.route("/confirm-deposit", methods=["GET", "POST"])
def confirm_deposit():
    if 'user_id' not in session:
        return redirect(url_for("login"))

    user = User.query.get(session['user_id'])

    if request.method == "POST":
        amount = float(request.form["amount"])
        txn = Transaction(
            user_id=user.id,
            amount=amount,
            status="Pending",
            timestamp=datetime.utcnow()
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
        user = User.query.get(txn.user_id)
        fee_percentage = 10  # This should be defined in a config file
        user.balance += txn.amount * ((100 - fee_percentage) / 100)
        db.session.commit()
        flash(f"Deposit of {txn.amount} approved.", "success")
    return redirect(url_for("admin_deposits"))

@app.route('/add_beneficiary', methods=['GET', 'POST'])
def add_beneficiary():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    form = AddBeneficiaryForm()  

    if form.validate_on_submit():  # ✅ Flask-WTF form validation
        try:
            new_beneficiary = Beneficiary(
                user_id=user.id,
                name=form.name.data,
                id_number=form.id_number.data,
                address=form.address.data,
                country=form.country.data,
                phone=form.phone.data,
                bank=form.bank.data,
                account=form.bank_account.data  # ✅ Fixed incorrect key
            )
            db.session.add(new_beneficiary)
            db.session.commit()

            flash("Beneficiary added successfully!", "success")
            return redirect(url_for('add_beneficiary'))  # ✅ Redirect back to the form
        
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding beneficiary: {str(e)}", "danger")

    beneficiaries = Beneficiary.query.filter_by(user_id=user.id).all()

    return render_template('add_beneficiary.html', user=user, beneficiaries=beneficiaries, form=form)

@app.route("/convert_zar_to_usdc", methods=["POST"])
def convert_zar_to_usdc():
    data = request.json
    zar_amount = float(data["amount"])

    # Fetch exchange rate from Luno
    zar_to_xlm_rate = get_luno_rate()
    if zar_to_xlm_rate == 0:
        return jsonify({"error": "Failed to fetch Luno rate"}), 400

    xlm_amount = zar_amount / zar_to_xlm_rate

    # Swap XLM for USDC on Stellar
    transaction = (
        TransactionBuilder(
            source_account=STELLAR_SERVER.load_account(STELLAR_SOURCE_KEYPAIR.public_key),
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100
        )
        .append_path_payment_strict_receive_op(
            destination=STELLAR_SOURCE_KEYPAIR.public_key,
            send_asset=Asset("XLM"),
            send_max=str(xlm_amount),
            dest_asset=STELLAR_ASSET_USDC,
            dest_amount="1"  # Target USDC amount
        )
        .set_timeout(30)
        .build()
    )

    transaction.sign(STELLAR_SOURCE_KEYPAIR)
    response = STELLAR_SERVER.submit_transaction(transaction)

    if response.get("successful", False):
        usdc_received = float(response["amount"])
        return jsonify({"usdc_received": usdc_received, "message": "ZAR converted to USDC successfully."})
    else:
        return jsonify({"error": "Conversion failed"}), 400

@app.route("/sell_usdc_for_usd", methods=["POST"])
def sell_usdc_for_usd():
    data = request.json
    usdc_amount = float(data["usdc_amount"])

    # Use Stellar Liquidity Pool to convert USDC to USD
    transaction = (
        TransactionBuilder(
            source_account=STELLAR_SERVER.load_account(STELLAR_SOURCE_KEYPAIR.public_key),
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100
        )
        .append_path_payment_strict_receive_op(
            destination=STELLAR_SOURCE_KEYPAIR.public_key,
            send_asset=STELLAR_ASSET_USDC,
            send_max=str(usdc_amount),
            dest_asset=Asset("USD"),
            dest_amount="1"
        )
        .set_timeout(30)
        .build()
    )

    transaction.sign(STELLAR_SOURCE_KEYPAIR)
    response = STELLAR_SERVER.submit_transaction(transaction)

    if response.get("successful", False):
        usd_received = float(response["amount"])
        return jsonify({"usd_received": usd_received, "message": "USDC converted to USD successfully."})
    else:
        return jsonify({"error": "Conversion failed"}), 400

@app.route("/calculate_final_amount", methods=["POST"])
def calculate_final_amount():
    try:
        data = request.json
        amount = float(data.get("amount", 0))
        method = data.get("method", "blockchain")  # Default to blockchain

        if amount <= 0:
            return jsonify({"error": "Invalid amount"}), 400

        # Fetch live exchange rates
        rates = get_live_exchange_rate()
        zar_usdt = rates["zar_usdt"]
        xlm_usdt = rates["xlm_usdt"]

        # Apply 10% fee
        total_cost = amount * (1 + UPFRONT_FEE_PERCENT / 100)

        # Convert to final currency
        if method == "blockchain":
            final_amount = (total_cost / zar_usdt) / xlm_usdt  # Convert ZAR → USDT → XLM
            currency = "XLM"
        elif method == "momo" or method == "bank":
            final_amount = total_cost / zar_usdt  # Convert ZAR → USDT
            currency = "USDT"
        else:
            return jsonify({"error": "Invalid method"}), 400

        return jsonify({
            "method": method,
            "total_cost": round(total_cost, 2),
            "final_amount": round(final_amount, 6),  # More precision for crypto
            "currency": currency,
            "message": "Final amount calculated successfully."
        })

    except Exception as e:
        logging.error(f"Error in calculate_final_amount: {e}")
        return jsonify({"error": "Failed to calculate final amount"}), 500

@app.route('/send_money', methods=['GET', 'POST'])
def send_money():
    form = SendMoneyForm()
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    exchange_rate = get_live_exchange_rate()
    beneficiaries = Beneficiary.query.filter_by(user_id=user.id).all()
    transaction_fee = 0.02  # 2% fee
    zar_usdt = rates["zar_usdt"]
    xlm_usdt = rates["xlm_usdt"]

    if form.validate_on_submit():
        amount_zar = float(form.amount.data)

        # Lock exchange rate at time of transaction
        locked_exchange_rate = zar_usdt_rate * (1 - transaction_fee)  # Deduct fee
        converted_amount = round(amount_zar * locked_exchange_rate, 2)

    if request.method == 'POST':
        amount_zar = float(request.form['amount'])
        beneficiary_id = request.form['beneficiary_id']
        payout_method = request.form['payout_method']

        if user.balance >= amount_zar:
            user.balance -= amount_zar
            db.session.commit()
            flash(f"Transaction successful! Sent {converted_amount} USD at {locked_exchange_rate} rate.", "success")
        else:
            flash("Insufficient balance!", "danger")

        # Deduct balance
        user.balance -= amount_zar
        db.session.commit()

        # Convert ZAR to final currency
        if payout_method == "blockchain":
            final_amount = (amount_zar / zar_usdt) / xlm_usdt  # Convert ZAR → USDT → XLM
            currency = "XLM"
        else:
            final_amount = amount_zar / zar_usdt  # Convert ZAR → USDT
            currency = "USDT"

        # Fetch beneficiary details
        beneficiary = Beneficiary.query.get(beneficiary_id)

        # Process payment via Stellar or MoMo
        if payout_method == "blockchain":
            response = send_stellar_payment(beneficiary.wallet_address, str(final_amount), asset="XLM")
        elif payout_method == "Mobile Money":
            response = process_mobile_money_transfer(beneficiary.phone, final_amount)
        else:  # Default to bank transfer
            response = process_bank_transfer(beneficiary.account, final_amount)

        flash("Money sent successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('send_money.html', user=user, beneficiaries=beneficiaries, exchange_rate=zar_usdt, form=form)

# ---- Updated Payment Processing Functions ----

def send_stellar_payment(wallet_address, amount, asset="XLM"):
    """ Process Stellar Blockchain Payment """
    print(f"Sending {amount} {asset} to {wallet_address} on Stellar Network")
    return f"Stellar transaction for {amount} {asset} sent to {wallet_address}"

def process_bank_transfer(account, amount):
    """ Mock function for bank transfer """
    print(f"Bank transfer of {amount} USD to {account}")
    return f"Bank transfer of {amount} USD to {account} initiated"

def process_mobile_money_transfer(phone, amount):
    """ Mock function for mobile money transfer """
    print(f"Mobile Money transfer of {amount} USD to {phone}")
    return f"Mobile Money transfer of {amount} USD to {phone} initiated"

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))  # Redirect if not logged in
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.id_number = request.form['id_number']
        user.passport_number = request.form['passport_number']
        user.address = request.form['address']
        user.country_code = request.form['country_code']
        user.phone_number = request.form['phone_number']
        user.bank_name = request.form['bank_name']
        user.bank_account_number = request.form['bank_account_number']
        
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to dashboard after update
    
    return render_template('edit_profile.html', user=user, form=form)

@app.route('/get_exchange_rate', methods=['GET'])
def get_exchange_rate():
    method = request.args.get('method')
    amount = request.args.get('amount')

    if not method or not amount:
        return jsonify({"error": "Missing parameters"}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({"error": "Amount must be greater than zero"}), 400
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

    # Get latest exchange rates from Luno & Stellar
    try:
        zar_usdt_rate = get_luno_rate("ZARUSDT") or 18.5  # Default ZAR to USDT if API fails
    except Exception:
        zar_usdt_rate = 18.5

    try:
        usdt_xlm_rate = get_stellar_price("USDT_XLM") or 10.0  # Default XLM price if API fails
    except Exception:
        usdt_xlm_rate = 10.0

    # Calculate different exchange rates based on method
    exchange_rates = {
        "bank": zar_usdt_rate,  # Standard ZAR to USDT conversion for bank payments
        "momo": zar_usdt_rate * 0.975,  # 2.5% discount for Mobile Money
        "blockchain": (1 / usdt_xlm_rate) * zar_usdt_rate  # Convert ZAR → USDT → XLM
    }

    rate = exchange_rates.get(method)
    if rate is None:
        return jsonify({"error": "Invalid method"}), 400

    converted_amount = amount / rate  # Convert from ZAR to target currency

    return jsonify({
        "method": method,
        "amount": amount,
        "exchange_rate": round(rate, 4),
        "converted_amount": round(converted_amount, 2)
    })


@app.route('/process', methods=['POST'])
def process_transaction():
    try:
        data = request.json  # Use JSON for safer data handling
        amount = float(data.get('amount', 0))
        beneficiary = data.get('beneficiary')
        method = data.get('method', 'blockchain')  # Default to blockchain if not provided

        if not amount or amount <= 0 or not beneficiary:
            return jsonify({'status': 'error', 'message': 'Invalid amount or beneficiary.'}), 400

        # --- Get Live Exchange Rates ---
        try:
            usd_zar_rate = get_luno_rate("ZAR", "USDT") or 18.5  # Luno API for fiat conversion
            xlm_usdt_rate = get_stellar_price() or 0.1  # Stellar XLM price in USDT
        except Exception:
            usd_zar_rate = 18.5  # Default rate if API fails
            xlm_usdt_rate = 0.1

        exchange_rates = {
            "bank": usd_zar_rate,
            "momo": usd_zar_rate * 0.975,  # MoMo discount (2.5% fee reduction)
            "blockchain": xlm_usdt_rate * usd_zar_rate  # Stellar conversion
        }

        if method not in exchange_rates:
            return jsonify({'status': 'error', 'message': 'Invalid payment method.'}), 400

        exchange_rate = exchange_rates[method]
        final_amount = amount / exchange_rate  # Convert ZAR to USD or XLM
        final_amount = apply_transaction_fee(final_amount, method)  # Deduct transaction fees

        # --- Process Payment Based on Method ---
        if method == "blockchain":
            response = send_stellar_payment(beneficiary, str(final_amount), asset="XLM")
        elif method == "momo":
            response = send_momo_payment(beneficiary, final_amount)
        else:
            response = send_bank_transfer(beneficiary, final_amount)

        return jsonify({
            'status': 'success',
            'method': method,
            'exchange_rate': round(exchange_rate, 4),
            'final_amount': round(final_amount, 2),
            'transaction_details': response
        })

    except Exception as e:
        logging.error(f'Error in processing transaction: {e}')
        return jsonify({'status': 'error', 'message': 'Transaction failed. Please try again.'}), 500


if __name__ == "__main__":
    import threading
    threading.Thread(target=background_deposit_checker, daemon=True).start()
    db.create_all()
    print("Database tables created successfully!")
    app.run(debug=True)
