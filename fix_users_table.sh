#!/bin/bash

# Database connection details
DB_SERVER="your_db_server"
DB_NAME="your_database"
DB_USER="your_username"
DB_PASSWORD="your_password"

# Check if required columns exist
echo "Checking if columns exist in the 'users' table..."
EXISTING_COLUMNS=$(sqlcmd -S $DB_SERVER -d $DB_NAME -U $DB_USER -P $DB_PASSWORD -Q "
    SELECT COLUMN_NAME 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'users' 
    AND COLUMN_NAME IN ('password_hash', 'account_number');" -h -1 -W
)

if [[ ! $EXISTING_COLUMNS =~ "password_hash" ]]; then
    echo "Adding missing column: password_hash"
    sqlcmd -S $DB_SERVER -d $DB_NAME -U $DB_USER -P $DB_PASSWORD -Q "
        ALTER TABLE users ADD password_hash VARCHAR(255);"
fi

if [[ ! $EXISTING_COLUMNS =~ "account_number" ]]; then
    echo "Adding missing column: account_number"
    sqlcmd -S $DB_SERVER -d $DB_NAME -U $DB_USER -P $DB_PASSWORD -Q "
        ALTER TABLE users ADD account_number VARCHAR(50);"
fi

# Apply Alembic migrations if needed
if [ -d "migrations" ]; then
    echo "Applying Alembic migrations..."
    alembic revision --autogenerate -m "Added password_hash and account_number"
    alembic upgrade head
else
    echo "Alembic not set up. Skipping migrations."
fi

# Restart the Flask app
echo "Restarting Flask app..."
pkill -f "flask run"
export FLASK_APP=app.py
flask run --host=0.0.0.0 --port=5000 &

echo "Done! Try logging in again."
