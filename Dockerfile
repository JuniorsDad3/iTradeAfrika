# Use an official Python image as a base
FROM python:3.11-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (only what you actually need)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Expose the port (default is 8000)
EXPOSE 8000

# Set default port in case $PORT is not provided by the environment
ENV PORT=8000

# Run the app using Gunicorn
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} app:app"]
