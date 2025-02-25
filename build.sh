#!/usr/bin/env bash
set -e

echo "Updating package lists..."
apt-get update -y

echo "Installing prerequisites..."
apt-get install -y apt-transport-https curl gnupg2 unixodbc unixodbc-dev

echo "Adding Microsoft repository..."
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

echo "Updating packages after adding Microsoft repo..."
apt-get update -y

echo "Installing ODBC Driver 18 for SQL Server and dependencies..."
ACCEPT_EULA=Y apt-get install -y msodbcsql18 odbcinst libodbc1

echo "Setting LD_LIBRARY_PATH..."
export LD_LIBRARY_PATH=/opt/microsoft/msodbcsql18/lib64:$LD_LIBRARY_PATH
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

echo "Listing installed ODBC drivers using odbcinst -q -d:"
odbcinst -q -d

echo "Listing contents of /opt/microsoft/msodbcsql18/lib64:"
ls -l /opt/microsoft/msodbcsql18/lib64 || echo "Directory not found"

echo "Starting Gunicorn..."
gunicorn app:app --bind 0.0.0.0:10000
