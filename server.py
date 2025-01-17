from flask import Flask, render_template, request, jsonify
import uuid
import dns.resolver
import smtplib
import os
import re
import jwt
import datetime
from concurrent.futures import ThreadPoolExecutor
from secrets import token_urlsafe
from email.mime.text import MIMEText
import socket

app = Flask(__name__)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random, secure key

# In-memory storage for simplicity
api_keys = {}
daily_limit = 1000

# Setup ThreadPoolExecutor to parallelize email validation tasks
executor = ThreadPoolExecutor(max_workers=10)  # Adjust the number of concurrent tasks

# Route for the API Key generation page
@app.route("/")
def index():
    return render_template("index.html")

# API endpoint to generate an API key (JWT)
@app.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    # Generate a secure token
    api_key = token_urlsafe(32)  # Strong API key generation
    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # 1 day expiration

    # Encode the JWT with expiration and key
    token = jwt.encode({'api_key': api_key, 'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
    api_keys[api_key] = {"used_today": 0}
    return jsonify({"api_key": token})

# Route for the Email Validation page
@app.route("/verify")
def verify_page():
    return render_template("verify.html")

# API endpoint to validate emails
@app.route("/api/verify", methods=["POST"])
def verify_emails():
    api_key_token = request.headers.get("API-Key")
    if not api_key_token:
        return jsonify({"error": "API key is missing"}), 403

    try:
        # Decode JWT and validate expiration
        decoded_token = jwt.decode(api_key_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        api_key = decoded_token['api_key']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "API key has expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid API key"}), 403

    if api_key not in api_keys:
        return jsonify({"error": "Invalid API key"}), 403

    if api_keys[api_key]["used_today"] >= daily_limit:
        return jsonify({"error": "Daily limit reached"}), 403

    data = request.json
    emails = data.get("emails", [])
    valid_emails = []
    invalid_emails = []

    # Use ThreadPoolExecutor to process emails in parallel
    futures = [executor.submit(validate_single_email, email) for email in emails]
    
    # Wait for all futures to complete and collect results
    for future in futures:
        result = future.result()
        if result["valid"]:
            valid_emails.append(result)
        else:
            invalid_emails.append(result["email"])

    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})

def validate_single_email(email):
    """Validates a single email address."""
    result = {"email": email}
    try:
        # Syntax Check
        if not is_valid_email_syntax(email):
            result["valid"] = False
            result["error"] = "Invalid email syntax"
            return result

        # MX Record Lookup
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)

        # SMTP Verification
        smtp_verified = verify_smtp(mx_record, email)

        # Blacklist Check (can use an external API or a list of known blacklisted domains)
        blacklisted = check_blacklist(domain)

        # Risk Scoring (based on various factors)
        risk_score = calculate_risk_score(smtp_verified, blacklisted)

        # If all checks are valid
        result.update({
            "valid": True,
            "mx_record": mx_record,
            "smtp_verified": smtp_verified,
            "blacklisted": blacklisted,
            "risk_score": risk_score
        })

    except dns.resolver.NoAnswer:
        result["valid"] = False
        result["error"] = "No MX record found for domain"
    except dns.resolver.NXDOMAIN:
        result["valid"] = False
        result["error"] = "Domain not found"
    except Exception as e:
        result["valid"] = False
        result["error"] = f"Error: {str(e)}"

    return result

def is_valid_email_syntax(email):
    """Check the basic syntax of an email address."""
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(regex, email))

def verify_smtp(mx_record, email):
    """Verify SMTP for the domain by simulating an email delivery (bounce-back detection)."""
    try:
        # Open an SMTP connection to the MX server
        with smtplib.SMTP(mx_record, timeout=10) as server:
            server.set_debuglevel(0)  # Disable debug output
            
            # Simulate the "MAIL FROM" and "RCPT TO" commands
            sender = "test@yourdomain.com"  # Your sending address (doesn't need to exist)
            recipient = email
            
            # Use EHLO to identify ourselves to the server
            server.ehlo()

            # Check if the recipient address is valid
            code, message = server.mail(sender)
            if code != 250:
                return False  # SMTP server rejected the sender

            code, message = server.rcpt(recipient)
            if code == 250:
                return True  # Email address is valid, no bounce-back
            else:
                return False  # Bounce-back or rejection from the recipient server

    except (smtplib.SMTPException, socket.error) as e:
        # Catch any errors with SMTP or connection failures
        return False

def check_blacklist(domain):
    """Dummy blacklist check. This should be replaced with a real blacklist API."""
    blacklisted_domains = ['example.com']
    return domain in blacklisted_domains

def calculate_risk_score(smtp_verified, blacklisted):
    """Calculate risk score based on SMTP verification and blacklist status."""
    score = 0
    if smtp_verified:
        score += 50
    if not blacklisted:
        score += 30
    return score

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))  # This line should now work correctly
