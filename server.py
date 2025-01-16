from flask import Flask, render_template, jsonify, request
import uuid
import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import asyncio
import aiosmtplib

app = Flask(__name__)

# API key storage and rate limiting
api_keys = {}
daily_limit = 1000

# Generate API Key
@app.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    api_key = str(uuid.uuid4())
    api_keys[api_key] = {"used_today": 0}
    return jsonify({"api_key": api_key})

# Render the index page
@app.route("/")
def index():
    return render_template("index.html")

# Render the verify page
@app.route("/verify")
def verify():
    return render_template("verify.html")

# Async function to send a test email
async def send_test_email(to_email, mx_record):
    try:
        sender_email = "your_email@gmail.com"  # Replace with your own email here
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = to_email
        message["Subject"] = "Test Email for Verification"
        body = "This is a test email to verify the validity of your email address."
        message.attach(MIMEText(body, "plain"))

        # Use aiosmtplib to send email asynchronously
        async with aiosmtplib.SMTP(hostname=mx_record, port=587, use_tls=True) as smtp:
            await smtp.sendmail(sender_email, to_email, message.as_string())
        return True  # If no error, email is valid
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
        return False  # Email is invalid if error occurs

# Function to get MX record and validate email domain
def get_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        return mx_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        print(f"MX record not found for domain: {domain}")
        return None

# API endpoint to verify emails
@app.route("/api/verify", methods=["POST"])
async def verify_emails():
    api_key = request.headers.get("API-Key")
    if not api_key or api_key not in api_keys:
        return jsonify({"error": "Invalid or missing API key"}), 403

    if api_keys[api_key]["used_today"] >= daily_limit:
        return jsonify({"error": "Daily limit reached"}), 403

    data = request.json
    emails = data.get("emails", [])
    valid_emails = []
    invalid_emails = []

    # Process emails concurrently
    tasks = []
    for email in emails:
        domain = email.split('@')[1]
        mx_record = get_mx_record(domain)

        if mx_record:
            task = asyncio.create_task(send_test_email(email, mx_record))
            tasks.append((email, task))
        else:
            invalid_emails.append(email)

    for email, task in tasks:
        result = await task
        if result:
            valid_emails.append(email)
        else:
            invalid_emails.append(email)

    # Update the daily usage limit
    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
