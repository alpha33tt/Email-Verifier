import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
from flask import Flask, jsonify, request, render_template
import os
import asyncio
import aiosmtplib

app = Flask(__name__)

# API key storage and rate limiting
api_keys = {}
daily_limit = 1000

# Serve the "Generate API Key" page (generate-api-key.html)
@app.route("/generate-api-key")
def generate_api_page():
    return render_template('generate-api-key.html')

# Serve the "Verify Email" page (verify.html)
@app.route("/verify")
def verify_page():
    return render_template('verify.html')

# Generate API Key
@app.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    api_key = str(uuid.uuid4())
    api_keys[api_key] = {"used_today": 0}
    return jsonify({"api_key": api_key})

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
def verify_emails():
    api_key = request.headers.get("API-Key")
    if not api_key or api_key not in api_keys:
        return jsonify({"error": "Invalid or missing API key"}), 403

    if api_keys[api_key]["used_today"] >= daily_limit:
        return jsonify({"error": "Daily limit reached"}), 403

    data = request.json
    emails = data.get("emails", [])
    valid_emails = []
    invalid_emails = []

    # Process emails in batches of 100 to avoid overloading the server
    batch_size = 100
    email_batches = [emails[i:i + batch_size] for i in range(0, len(emails), batch_size)]

    for batch in email_batches:
        for email in batch:
            domain = email.split('@')[1]
            mx_record = get_mx_record(domain)

            if mx_record:
                # If MX record is found, send a test email to verify the email
                result = asyncio.run(send_test_email(email, mx_record))
                if result:
                    valid_emails.append(email)
                else:
                    invalid_emails.append(email)
            else:
                # If MX record is not found, mark email as invalid
                invalid_emails.append(email)

    # Update the daily usage limit
    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
