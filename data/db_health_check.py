import argparse
import pandas as pd
import sys
from pathlib import Path

def load_db(path):
    try:
        xls = pd.read_excel(path, sheet_name=None, engine='openpyxl')
        return xls
    except Exception as e:
        print(f"❌ Failed to load database file: {e}")
        sys.exit(1)


def check_sheets(xls, required_sheets):
    missing = [s for s in required_sheets if s not in xls]
    if missing:
        print(f"❌ Missing sheets: {', '.join(missing)}")
    else:
        print(f"✅ All required sheets present: {', '.join(required_sheets)}")


def check_columns(xls, schema):
    for sheet, cols in schema.items():
        df = xls.get(sheet)
        if df is None:
            continue
        missing = [c for c in cols if c not in df.columns]
        if missing:
            print(f"❌ Sheet '{sheet}' missing columns: {', '.join(missing)}")
        else:
            print(f"✅ Sheet '{sheet}' contains all required columns")


def check_duplicates(xls, key_columns):
    for sheet, keys in key_columns.items():
        df = xls.get(sheet)
        if df is None or df.empty:
            continue
        dupes = df.duplicated(subset=keys).sum()
        if dupes:
            print(f"⚠️ {dupes} duplicate rows found in '{sheet}' on keys {keys}")
        else:
            print(f"✅ No duplicates found in '{sheet}' on keys {keys}")


def check_balances(xls):
    users = xls.get('users')
    transactions = xls.get('transactions')
    if users is None or transactions is None:
        return

    # Compute net deposits and withdrawals per user
    txns = transactions.copy()
    txns['amount'] = pd.to_numeric(txns['amount'], errors='coerce').fillna(0)
    deposits = txns[txns['transaction_type']=='Deposit'].groupby('user_id')['amount'].sum()
    withdrawals = txns[txns['transaction_type']=='Transfer'].groupby('user_id')['amount'].sum()
    balances = users.set_index('id')['balance']

    inconsistencies = []
    for uid in balances.index:
        expected = deposits.get(uid, 0) - withdrawals.get(uid, 0)
        actual = balances.loc[uid]
        if round(expected, 2) != round(actual, 2):
            inconsistencies.append((uid, expected, actual))

    if inconsistencies:
        print("⚠️ Balance inconsistencies found:")
        for uid, exp, act in inconsistencies:
            print(f"  - User {uid}: expected {exp}, actual {act}")
    else:
        print("✅ All user balances consistent with transactions")


def main():
    parser = argparse.ArgumentParser(description="iTradeAfrika DB Health Check")
    parser.add_argument('db_path', type=str, help='Path to itrade_db.xlsx')
    args = parser.parse_args()

    path = Path(args.db_path)
    if not path.exists():
        print(f"❌ File not found: {path}")
        sys.exit(1)

    xls = load_db(path)

    required_sheets = ['users', 'beneficiaries', 'transactions', 'LiveRates']
    schema = {
        'users': ['id', 'username', 'email', 'password_hash', 'account_number', 'balance', 'created_at'],
        'beneficiaries': ['id', 'user_id', 'name', 'bank_account', 'currency'],
        'transactions': ['id', 'user_id', 'beneficiary_id', 'amount', 'final_amount', 'currency', 'transaction_type', 'status', 'timestamp'],
        'LiveRates': ['timestamp', 'source', 'rate_type', 'rate_value']
    }
    key_columns = {
        'users': ['id'],
        'beneficiaries': ['id'],
        'transactions': ['id'],
    }

    print(f"🔍 Checking database at {path}\n")
    check_sheets(xls, required_sheets)
    print()
    check_columns(xls, schema)
    print()
    check_duplicates(xls, key_columns)
    print()
    check_balances(xls)

if __name__ == '__main__':
    main()
