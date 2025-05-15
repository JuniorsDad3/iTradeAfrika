import smtplib, os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

print("Testing SMTP login for:", MAIL_USERNAME)

try:
    server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
    server.starttls()
    server.login(MAIL_USERNAME, MAIL_PASSWORD)
    print("✅ SMTP login successful!")
    server.quit()
except Exception as e:
    print("❌ SMTP login failed:", e)
