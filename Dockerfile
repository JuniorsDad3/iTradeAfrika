# Use an official Python image as a base
FROM python:3.11-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies and ODBC driver prerequisites
RUN apt-get update && apt-get install -y \
    apt-transport-https \
    curl \
    gnupg2 \
    unixodbc \
    unixodbc-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Add the Microsoft repository and install ODBC Driver 18 for SQL Server
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 odbcinst libodbc1 \
    && rm -rf /var/lib/apt/lists/*

# Set the library path so that the driver can be found
ENV LD_LIBRARY_PATH=/opt/microsoft/msodbcsql18/lib64:$LD_LIBRARY_PATH

# Set the working directory
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Expose the correct port (default is 8000)
EXPOSE 8000

# Set a default port in case $PORT is not provided by the environment
ENV PORT=8000

# Command to run your application using Gunicorn
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} app:app"]
