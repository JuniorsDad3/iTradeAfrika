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
from flask_mail import Mail, Message
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
import secrets
import luno_python
from requests.auth import HTTPBasicAuth
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key")


DB_FILE = Path(__file__).parent / "data" / "itrade_db.xlsx"
DB_FILE.parent.mkdir(exist_ok=True)

csrf = CSRFProtect(app)
mail = Mail(app)

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
        # create an empty workbook with our three sheets
        with pd.ExcelWriter(DB_FILE, engine="openpyxl") as writer:
            for name in ("Users", "beneficiaries", "Transactions"):
                pd.DataFrame().to_excel(writer, sheet_name=name, index=False)
    return pd.read_excel(DB_FILE, sheet_name=sheet)

def save_sheet(df: pd.DataFrame, sheet: str):
    """
    Overwrite one sheet in the workbook by:
      1) reading all sheets into a dict
      2) replacing the named sheet
      3) writing all sheets back out
    """
    all_sheets: dict[str, pd.DataFrame] = pd.read_excel(DB_FILE, sheet_name=None)
    all_sheets[sheet] = df

    with pd.ExcelWriter(DB_FILE, engine="openpyxl") as writer:
        for name, sheet_df in all_sheets.items():
            sheet_df.to_excel(writer, sheet_name=name, index=False)

def generate_unique_account_number() -> str:
    """Return a new ITRADE-######## number not yet in the Users sheet."""
    users = load_df("Users")
    existing = set(users["account_number"].astype(str)) if "account_number" in users.columns else set()
    while True:
        candidate = "ITRADE-" + "".join(random.choices(string.digits, k=8))
        if candidate not in existing:
            return candidate

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
    beneficiary_id = SelectField('Select Beneficiary', coerce=int)  # This is fine if IDs are integers
    submit = SubmitField('Send Money')

class EditProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Update Profile")

class AddBeneficiaryForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[
        ("USD", "USD"),
        ("EUR", "EUR"),
        ("BWP", "BWP")
    ], validators=[DataRequired()])
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


def send_email(to_email, subject, body):
    from_email = app.config['MAIL_USERNAME']
    password   = app.config['MAIL_PASSWORD']

    msg = MIMEMultipart()
    msg["From"]    = from_email
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))  # use HTML if you send <p> tags

    try:
        # choose SSL vs TLS based on config
        if app.config['MAIL_USE_SSL']:
            server = smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            if app.config['MAIL_USE_TLS']:
                server.starttls()

        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
        app.logger.info(f"Email sent to {to_email}")
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")

@app.route('/')
def home():
    return render_template("index.html") 

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        users = load_df("Users")

        app.logger.debug(f"Attempting registration: username={form.username.data}, email={form.email.data}")


        # Prevent duplicate usernames
        if form.username.data in users["username"].values:
            flash("Username already taken", "danger")
            return render_template("register.html", form=form)

        # Build new user record
        new = {
            "id": str(uuid.uuid4()),
            "username": form.username.data,
            "email": form.email.data,
            "password_hash": generate_password_hash(form.password.data),
            "account_number": "ITRADE-" + ''.join(random.choices(string.digits, k=8)),
            "balance": 0.0,
            "created_at": datetime.utcnow()
        }


        app.logger.debug(f"Generated account: {new['account_number']}")
        app.logger.debug(f"Password hash: {new['password_hash']}")

        # Append, save, and notify
        users = pd.concat([users, pd.DataFrame([new])], ignore_index=True)
        save_sheet(users, "Users")
        flash("Registration successful! Please log in.", "success")

        # Send welcome email
        send_email(
            form.email.data,
            "Welcome to iTradeAfrika!",
            (
                f"<p>Hi {form.username.data},</p>"
                f"<p>Thanks for registering! Your account number is "
                f"<strong>{new['account_number']}</strong>.</p>"
            )
        )

        # Go to login
        return redirect(url_for("login"))

    # GET or validation errors
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        users = load_df("Users")
        users.columns = users.columns.str.strip()

        app.logger.debug(f"Login attempt for username: {form.username.data}")

        # Match trimmed username
        row = users[users["username"].str.strip() == form.username.data.strip()]
        if row.empty:
            flash("Invalid username or password", "danger")
            return render_template("login.html", form=form)

        stored_hash = str(row.iloc[0]["password_hash"]).strip()
        entered_pw = form.password.data.strip()

        app.logger.debug(f"Stored hash: {repr(stored_hash)}")
        app.logger.debug(f"Entered password: {repr(entered_pw)}")

        if stored_hash and check_password_hash(stored_hash, entered_pw):
            session["user_id"] = row.iloc[0]["id"]  # make sure this matches everywhere
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route("/deposit", methods=["POST"])
def deposit():
    # 1) Must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # 2) Validate amount
    try:
        amt = float(request.form["amount"])
        if amt <= 0:
            raise ValueError("Amount must be positive")
    except:
        flash("Invalid amount", "danger")
        return redirect(url_for("dashboard"))

    # 3) Load users, find current user
    users = load_df("Users")
    user_idx_list = users.index[users["id"] == session["user_id"]]
    if not len(user_idx_list):
        flash("User not found", "danger")
        return redirect(url_for("dashboard"))
    idx = user_idx_list[0]

    # 4) Update balance and save
    users.at[idx, "balance"] += amt
    save_sheet(users, "Users")

    # 5) Send confirmation email
    user_row = users.loc[idx]
    send_email(
        user_row["email"],
        "Deposit Confirmed",
        (
            f"<p>You have successfully deposited ZAR {amt:.2f} on "
            f"{datetime.utcnow():%Y-%m-%d %H:%M}.</p>"
        )
    )

    # 6) Record the transaction
    txns = load_df("Transactions")   # keep consistency with load_df
    new_txn = {
        "id":              str(uuid.uuid4()),
        "user_id":         session["user_id"],
        "beneficiary_id":  "",
        "amount":          amt,
        "final_amount":    "",
        "currency":        "ZAR",
        "transaction_type":"Deposit",
        "status":          "Success",
        "timestamp":       datetime.utcnow()
    }
    txns = pd.concat([txns, pd.DataFrame([new_txn])], ignore_index=True)
    save_sheet(txns, "Transactions")

    # 7) Flash success & redirect
    flash(f"Deposited ZAR {amt:.2f}", "success")
    return redirect(url_for("dashboard"))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    df = pd.read_excel(DB_FILE)
    user_id = session['user_id']
    user = df[df['id'] == user_id]

    if user.empty:
        return "User not found", 404

    user_data = user.iloc[0]
    form = EditProfileForm(data={
        'username': user_data['username'],
        'email': user_data['email']
    })

    if form.validate_on_submit():
        df.loc[df['id'] == user_id, 'username'] = form.username.data
        df.loc[df['id'] == user_id, 'email'] = form.email.data
        df.to_excel(DB_FILE, index=False)
        flash("Profile updated successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', user=user_data, form=form)


@app.route("/add_beneficiary", methods=["GET", "POST"])
def add_beneficiary():
    if "user_id" not in session:
        return redirect(url_for("login"))

    form = AddBeneficiaryForm()

    if form.validate_on_submit():
        # Instead of request.form[…], use form.name.data, form.bank_account.data, etc.
        name = form.name.data
        acct = form.bank_account.data
        curr = form.currency.data
        uid  = session["user_id"]

    if request.method == "POST":
        name = request.form.get("full_name")
        acct = request.form.get("account_number")
        curr = request.form["currency"]
        uid = session["user_id"]

        # Load, append, and save
        bens = load_df("Beneficiaries")
        new_ben = {
            "id":           str(uuid.uuid4()),
            "user_id": str(uid).strip(),
            "name":         name,
            "bank_account": acct,
            "currency":     curr
        }
        bens = pd.concat([bens, pd.DataFrame([new_ben])], ignore_index=True)

        save_sheet(bens, "beneficiaries")

        # Send notification email
        users = load_df("Users")
        user = users[users["id"] == uid].iloc[0]
        send_email(
            user["email"],
            "New Beneficiary Added",
            (
                f"<p>You just added <strong>{name}</strong> "
                f"(Acct: {acct}) as a beneficiary.</p>"
            )
        )

        flash("Beneficiary added", "success")
        return redirect(url_for("dashboard"))

    # GET
    return render_template("add_beneficiary.html", form=form)


# ✅ Define this helper at top of your file
def convert_crypto_to_fiat(crypto_amount, target_currency):
    rates = get_live_exchange_rates()
    rate = rates.get(target_currency, 1)  # fallback
    final_amount = crypto_amount * rate * 0.98  # 2% spread
    return round(final_amount, 2)

@app.route("/send_money", methods=["GET", "POST"])
def send_money():
    if "user_id" not in session:
        return redirect(url_for("login"))

    users = load_df("Users")
    users.columns = users.columns.str.strip()
    user = users[users["id"] == session["user_id"]].iloc[0]

    # Load and filter beneficiaries
    bens = load_df("Beneficiaries")
    bens["user_id"] = bens["user_id"].astype(str).str.strip()
    uid = str(session["user_id"]).strip()
    my_bens = bens[bens["user_id"] == uid]

    if request.method == "POST":
        # Parse inputs
        try:
            amt = float(request.form["amount"])
            bid = request.form["beneficiary_id"]
        except:
            flash("Invalid input", "danger")
            return redirect(url_for("send_money"))

        # Verify beneficiary belongs to user
        if bid not in my_bens["id"].astype(str).values:
            flash("Invalid beneficiary", "danger")
            return redirect(url_for("send_money"))

        # Calculate fee, lookup rate, compute payout
        amt_after = amt * 0.90  # 10% fee
        ben = my_bens[my_bens["id"] == bid].iloc[0]
        cur = ben["currency"]
        rates = load_df("LiveRates")
        rate = float(rates.loc[rates["currency"] == cur, "rate"].iloc[0])
        payout = round(amt_after * rate, 2)

        # Deduct from sender balance
        users = load_df("Users")
        idx = users.index[users["id"] == session["user_id"]][0]
        if users.at[idx, "balance"] < amt:
            flash("Insufficient funds", "danger")
            return redirect(url_for("send_money"))
        users.at[idx, "balance"] -= amt
        save_df(users, "Users")

        # Record transaction
        txns = load_df("Transactions")
        new_txn = {
            "id":              str(uuid.uuid4()),
            "user_id":         session["user_id"],
            "beneficiary_id":  bid,
            "amount":          amt,
            "final_amount":    payout,
            "currency":        cur,
            "transaction_type":"Transfer",
            "status":          "Success",
            "timestamp":       datetime.utcnow()
        }
        txns = pd.concat([txns, pd.DataFrame([new_txn])], ignore_index=True)
        save_df(txns, "Transactions")

        # Send confirmation email
        user = users.loc[idx]
        send_email(
            user["email"],
            "Transfer Successful",
            (
                f"<p>You have sent {payout} {cur} to your beneficiary "
                f"on {datetime.utcnow():%Y-%m-%d %H:%M}.</p>"
            )
        )

        # ✅ These must be inside the POST block
        flash(f"Transfer to {ben['name']} successful!", "success")
        return redirect(url_for("dashboard"))

    # GET request
    return render_template("send_money.html", user=user, beneficiaries=my_bens.to_dict("records"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    uid = str(session["user_id"]).strip()

    users = load_df("Users")
    user = users[users["id"] == uid].iloc[0]

    txns = load_df("Transactions")
    user_txns = txns[txns["user_id"] == uid].sort_values("timestamp", ascending=False)

    bens = load_df("Beneficiaries")
    bens["user_id"] = bens["user_id"].astype(str).str.strip()
    my_bens = bens[bens["user_id"] == uid]

    # Live crypto exchange rate (e.g., ZAR to USDT)
    latest_rate = get_luno_crypto_rate()  # Assumes a numeric return value
    zar_balance = user["balance"]
    balance_after_fee = zar_balance * 0.90
    converted_usdt = round(balance_after_fee / latest_rate, 2) if latest_rate else 0
    fees = zar_balance - balance_after_fee

    return render_template(
        "dashboard.html",
        user=user,
        transactions=user_txns.to_dict(orient="records"),
        exchange_rate=latest_rate,
        converted_usdt=converted_usdt,
        fees=fees,
        beneficiaries=my_bens.to_dict(orient="records")  # use filtered beneficiaries
    )

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
    # --- Ensure our Excel-backed sheets exist with the correct columns ---
    initial_sheets = {
        "Users":         ["id", "username", "email", "password_hash", "account_number", "balance", "created_at"],
        "beneficiaries": ["id", "user_id", "name", "bank_account", "currency"],
        "Transactions":  ["id", "user_id", "beneficiary_id", "amount", "final_amount", "currency", "transaction_type", "status", "timestamp"],
    }

    # If our workbook doesn't exist, create it with empty sheets.
    from pandas import ExcelFile  # noqa: F811
    if not DB_FILE.exists():
        # Use our load_df helper to bootstrap
        _ = load_df("Users")  # this will create the file and empty sheets
    else:
        # If it does exist, make sure each sheet has at least the right columns
        existing = ExcelFile(DB_FILE).sheet_names
        for name, cols in initial_sheets.items():
            if name not in existing:
                # write an empty sheet
                import pandas as pd
                with pd.ExcelWriter(DB_FILE, engine="openpyxl", mode="a") as w:
                    pd.DataFrame(columns=cols).to_excel(w, sheet_name=name, index=False)

    # --- Launch Flask ---
    port = os.getenv("PORT", "8000")
    if not port.isdigit():
        port = "8000"

    app.run(host="0.0.0.0", port=int(port), debug=False)