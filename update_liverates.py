import pandas as pd
from pathlib import Path
import requests
import logging

EXCHANGE_RATE_API_URL = "https://api.exchangerate-api.com/v4/latest/USD"
DB_FILE = Path(__file__).parent / "data" / "itrade_db.xlsx"

def get_live_exchange_rates():
    try:
        response = requests.get(EXCHANGE_RATE_API_URL)
        response.raise_for_status()
        rates = response.json().get("rates", {})
        return rates if rates else {}
    except Exception as e:
        logging.error(f"Error fetching exchange rates: {e}")
        return {}

def update_live_rates_sheet():
    rates = get_live_exchange_rates()
    if not rates:
        print("❌ No rates fetched. Aborting.")
        return

    # Filter only supported currencies
    supported = ["USD", "EUR", "GBP", "BWP", "CNY"]
    filtered_rates = [{"currency": cur, "rate": float(rates[cur])} for cur in supported if cur in rates]
    df = pd.DataFrame(filtered_rates)

    try:
        # Replace or create the "LiveRates" sheet safely
        with pd.ExcelWriter(DB_FILE, engine="openpyxl", mode="a", if_sheet_exists="replace") as writer:
            df.to_excel(writer, sheet_name="LiveRates", index=False)
        print("✅ LiveRates sheet updated successfully.")
    except FileNotFoundError:
        print(f"❌ Excel file not found at: {DB_FILE}")
    except Exception as e:
        print(f"❌ Failed to update sheet: {e}")

if __name__ == "__main__":
    update_live_rates_sheet()
