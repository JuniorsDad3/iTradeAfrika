from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import check_password_hash, generate_password_hash
from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from twilio.rest import Client as TwilioClient
from dotenv import load_dotenv
from flask_login import login_required
from pathlib import Path
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
import luno_python
from requests.auth import HTTPBasicAuth
import pandas as pd

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key")


DB_FILE = os.path.join(os.path.dirname(__file__), "data", "itrade_db.xlsx")
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_FILE = DATA_DIR / "itrade_db.xlsx"

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
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')


# --- Excel-backed helpers ---
# ───────────── DATA ACCESS LAYER ─────────
def load_df(sheet: str) -> pd.DataFrame:
    if not DB_FILE.exists():
        # Initialize empty sheets
        with pd.ExcelWriter(DB_FILE) as writer:
            for sheet_name in ("Users", "beneficiaries", "Transactions"):
                pd.DataFrame().to_excel(writer, sheet_name=sheet_name, index=False)
    return pd.read_excel(DB_FILE, sheet_name=sheet)

def save_df(df: pd.DataFrame, sheet: str):
    with pd.ExcelWriter(DB_FILE, mode="a", if_sheet_exists="replace") as writer:
        df.to_excel(writer, sheet_name=sheet, index=False)

def generate_unique_account_number() -> str:
    """Return a new ITRADE-######## account number not yet in Users sheet."""
    users = load_df("Users")
    existing = set(users["account_number"].astype(str).tolist())
    while True:
        candidate = "ITRADE-" + "".join(random.choices(string.digits, k=8))
        if candidate not in existing:
            return candidate

def save_sheet(df, name):
    # rewrite just this sheet, preserve others
    # openpyxl must be installed
    from openpyxl import load_workbook
    if not os.path.exists(DB_FILE):
        # create new with this sheet
        with pd.ExcelWriter(DB_FILE, engine="openpyxl") as w:
            df.to_excel(w, sheet_name=name, index=False)
        return
    book = load_workbook(DB_FILE)
    with pd.ExcelWriter(DB_FILE, engine="openpyxl", mode="a", if_sheet_exists="replace") as w:
        w.book = book
        df.to_excel(w, sheet_name=name, index=False)
        w.save()
# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class DepositForm(FlaskForm):
    amount = DecimalField("Amount (ZAR)", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Deposit")

class SendMoneyForm(FlaskForm):
    amount = DecimalField("Amount (ZAR)", validators=[DataRequired(), NumberRange(min=1)])
    beneficiary_id = SelectField("Beneficiary", coerce=str, validators=[DataRequired()])
    submit = SubmitField("Send")

class User:
    def generate_unique_account_number():
        users = load_df("Users")
        while True:
            acct = "ITRADE-" + "".join(random.choices(string.digits, k=8))
            if "account_number" not in users.columns:
                return acct
            if acct not in users["account_number"].astype(str).values:
                return acct

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

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        users = load_sheet("Users")
        # look for existing username
        if form.username.data in users.get("username", []):
            flash("Username already taken", "danger")
        else:
            # build new user row
            new = {
                "id": str(uuid.uuid4()),
                "username": form.username.data,
                "email": form.email.data,
                "password_hash": generate_password_hash(form.password.data),
                "account_number": "ITRADE-" + ''.join(random.choices(string.digits, k=8)),
                "balance": 0.0,
                "created_at": datetime.utcnow()
            }
            users = pd.concat([users, pd.DataFrame([new])], ignore_index=True)
            save_sheet(users, "Users")
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        users = load_sheet("Users")
        row = users[users["username"] == form.username.data]
        if row.empty:
            flash("Invalid username or password", "danger")
        else:
            stored_hash = row.iloc[0]["password_hash"]
            if check_password_hash(stored_hash, form.password.data):
                session["user_ID"] = row.iloc[0]["id"]
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password", "danger")
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    session.pop('user_ID', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/deposit', methods=['POST'])
def deposit():
    # load users & transactions
    users = load_sheet("Users")
    txns = load_sheet("Transactions")

    # find current user row
    uid = session['user_ID']
    idx = users.index[users['id'] == uid]
    if idx.empty:
        flash("User not found", "danger")
        return redirect(url_for('dashboard'))

    amount = float(request.form['amount'])
    users.at[idx[0], 'balance'] += amount
    save_sheet(users, "Users")

    # append transaction
    new_txn = {
        "id": str(uuid.uuid4()),
        "user_id": uid,
        "beneficiary_id": "",
        "amount": amount,
        "final_amount": "",
        "currency": "ZAR",
        "transaction_type": "Deposit",
        "status": "Success",
        "timestamp": datetime.utcnow()
    }
    txns = pd.concat([txns, pd.DataFrame([new_txn])], ignore_index=True)
    save_sheet(txns, "Transactions")

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


@app.route("/add_beneficiary", methods=["GET", "POST"])
def add_beneficiary():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form["name"]
        acct = request.form["bank_account"]
        curr = request.form["currency"]
        uid = session["user_id"]
        bens = load_df("Beneficiaries")
        bens = bens.append({
            "id": str(uuid.uuid4()),
            "user_id": uid,
            "name": name,
            "bank_account": acct,
            "currency": curr
        }, ignore_index=True)
        save_df(bens, "Beneficiaries")
        flash("Beneficiary added", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_beneficiary.html")

# ✅ Define this function at the top of your app.py before using it
def convert_crypto_to_fiat(crypto_amount, target_currency):
    rates = get_live_exchange_rates()
    rate = rates.get(target_currency, 1)  # Default fallback rate
    final_amount = crypto_amount * rate * 0.98  # Apply 2% spread for profit
    return round(final_amount, 2)

@app.route("/send_money", methods=["GET", "POST"])
def send_money():
    if "user_id" not in session:
        return redirect(url_for("login"))
    uid = session["user_id"]
    bens = load_df("Beneficiaries")
    user_bens = bens[bens["user_id"] == uid]
    form = SendMoneyForm()
    form.beneficiary_id.choices = [(b["id"], f"{b['name']} ({b['currency']})") for _, b in user_bens.iterrows()]
    if form.validate_on_submit():
        amt = float(form.amount.data)
        bid = form.beneficiary_id.data
        users = load_df("Users")
        bal = users.loc[users["id"] == uid, "balance"].iloc[0]
        if amt > bal:
            flash("Insufficient balance", "danger")
        else:
            # fee & payout
            net = amt * 0.90
            # exchange: lookup live rate from sheet or API stub
            rates = load_df("Rates") if "Rates" in pd.ExcelFile(DB_FILE).sheet_names else None
            currency = user_bens[user_bens["id"] == bid].iloc[0]["currency"]
            rate = float(rates.loc[rates["currency"] == currency, "rate"].iloc[0]) if rates is not None else 1
            payout = round(net * rate, 2)
            # update balance
            users.loc[users["id"] == uid, "balance"] -= amt
            save_df(users, "Users")
            # record txn
            txns = load_df("Transactions")
            txns = txns.append({
                "id": str(uuid.uuid4()),
                "user_id": uid,
                "beneficiary_id": bid,
                "amount_zar": amt,
                "final_payout": payout,
                "currency": currency,
                "type": "Transfer",
                "timestamp": pd.Timestamp.now()
            }, ignore_index=True)
            save_df(txns, "Transactions")
            flash(f"Sent {payout} {currency}", "success")
            return redirect(url_for("dashboard"))
    return render_template("send_money.html", form=form)

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    uid = session["user_id"]
    users = load_df("Users")
    user = users[users["id"] == uid].iloc[0]
    txns = load_df("Transactions")
    user_txns = txns[txns["user_id"] == uid].sort_values("timestamp", ascending=False)
    bens = load_df("Beneficiaries")
    return render_template("dashboard.html",
                           user=user,
                           transactions=user_txns.to_dict(orient="records"),
                           beneficiaries=bens.to_dict(orient="records"))
    
    # For live rates (example: using Luno rate)
    latest_rate = get_luno_crypto_rate()  # This should return a valid number
    zar_balance = user.balance
    balance_after_fee = zar_balance * 0.90
    converted_usdt = round(balance_after_fee / latest_rate, 2) if latest_rate else 0
    
    return render_template("dashboard.html", user=user, transactions=transactions, 
                           exchange_rate=latest_rate, converted_usdt=converted_usdt, 
                           fees=zar_balance - balance_after_fee, beneficiaries=beneficiaries)


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
    for sheet, cols in {
        "Users": ["id","username","email","password","balance"],
        "Beneficiaries": ["id","user_id","name","bank_account","currency"],
        "Transactions": ["id","user_id","beneficiary_id","amount_zar","final_payout","currency","type","timestamp"],
        "Rates": ["currency","rate"]
    }.items():
        if sheet not in pd.ExcelFile(DB_FILE).sheet_names:
            pd.DataFrame(columns=cols).to_excel(DB_FILE, sheet_name=sheet, index=False)

    # Ensure port is correctly handled
    port = os.getenv("PORT", "8000")  # Get PORT as a string, default to "8000"
    if not port.isdigit():  
        port = "8000"  # Default to "8000" if invalid

    app.run(host="0.0.0.0", port=int(port), debug=False)