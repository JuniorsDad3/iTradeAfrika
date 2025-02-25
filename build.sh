#!/usr/bin/env bash
set -e

echo "Updating package lists..."
apt-get update -y

echo "Installing prerequisites..."
apt-get install -y curl gnupg2 unixodbc unixodbc-dev

echo "Adding Microsoft repository..."
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

echo "Updating package lists after adding Microsoft repo..."
apt-get update -y

echo "Installing ODBC Driver 18 for SQL Server..."
ACCEPT_EULA=Y apt-get install -y msodbcsql18 odbcinst libodbc1

echo "Listing installed ODBC drivers:"
odbcinst -q -d

echo "Starting the application..."
gunicorn app:app --bind 0.0.0.0:10000
