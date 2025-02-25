@echo off
setlocal

:: Set database credentials
set DB_SERVER=your_db_server
set DB_NAME=your_database
set DB_USER=your_username
set DB_PASSWORD=your_password

:: Check if columns exist in the users table
echo Checking if columns exist in 'users' table...
sqlcmd -S %DB_SERVER% -d %DB_NAME% -U %DB_USER% -P %DB_PASSWORD% -Q ^
"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users' AND COLUMN_NAME IN ('password_hash', 'account_number');"

:: Add missing columns if needed
sqlcmd -S %DB_SERVER% -d %DB_NAME% -U %DB_USER% -P %DB_PASSWORD% -Q ^
"IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'password_hash') ALTER TABLE users ADD password_hash VARCHAR(255);"

sqlcmd -S %DB_SERVER% -d %DB_NAME% -U %DB_USER% -P %DB_PASSWORD% -Q ^
"IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'account_number') ALTER TABLE users ADD account_number VARCHAR(50);"

:: Apply Alembic migrations if needed
if exist "migrations" (
    echo Applying Alembic migrations...
    call alembic revision --autogenerate -m "Added password_hash and account_number"
    call alembic upgrade head
) else (
    echo Alembic not found. Skipping migrations.
)

:: Restart Flask app
taskkill /F /IM "python.exe"
timeout /t 2
start cmd /k "flask run --host=0.0.0.0 --port=5000"

echo Done! Try logging in again.
exit
