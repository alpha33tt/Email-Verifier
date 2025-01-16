import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
from flask import Flask, jsonify, request
import os

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

# Send a test email to verify SMTP
def send_test_email(to_email, mx_record):
    try:
        # Set up the test email content
        sender_email = "cardonewhite081@gmail.com"  # Use your own email here
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = to_email
        message["Subject"] = "Test Email for Verification"
        body = "This is a test email to verify the validity of your email address."
        message.attach(MIMEText(body, "plain"))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(mx_record) as server:
            server.set_debuglevel(0)  # Don't show debug output
            server.starttls()  # Encrypt the connection
            server.sendmail(sender_email, to_email, message.as_string())
            return True  # If no error, email is valid
    except smtplib.SMTPException as e:
        print(f"Error sending email: {e}")
        return False  # Email is invalid if error occurs

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
    email_batches = [emails[i:i+batch_size] for i in range(0, len(emails), batch_size)]
    
    for batch in email_batches:
        for email in batch:
            domain = email.split('@')[1]
            try:
                # Get MX record for the domain
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_record = str(mx_records[0].exchange)

                # Send a test email to validate the email
                if send_test_email(email, mx_record):
                    valid_emails.append(email)
                else:
                    invalid_emails.append(email)

            except Exception as e:
                invalid_emails.append(email)

    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
