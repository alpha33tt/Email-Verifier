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
    
    # Step 1: Syntax Check
    if not is_valid_email_syntax(email):
        result["valid"] = False
        result["error"] = "Invalid email syntax"
        return result

    try:
        # Step 2: MX Record Lookup (check if the domain has mail exchange records)
        domain = email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_record = str(mx_records[0].exchange)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["valid"] = False
            result["error"] = "No MX records found for domain"
            return result

        # Step 3: SMTP Verification (check if the mail server is reachable)
        smtp_verified = verify_smtp(mx_record)

        # Step 4: Blacklist Check
        blacklisted = check_blacklist(domain)

        # Step 5: Risk Scoring
        risk_score = calculate_risk_score(smtp_verified, blacklisted)

        # If all checks pass, mark as valid
        result.update({
            "valid": True,
            "mx_record": mx_record,
            "smtp_verified": smtp_verified,
            "blacklisted": blacklisted,
            "risk_score": risk_score
        })

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    return result

def is_valid_email_syntax(email):
    """Check the basic syntax of an email address."""
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(regex, email))

def verify_smtp(mx_record):
    """Verify SMTP for the domain (simplified version)."""
    try:
        # Attempting connection to the SMTP server
        smtp = smtplib.SMTP(mx_record, timeout=10)  # Adding timeout to prevent hanging
        smtp.set_debuglevel(0)  # Optional, for debugging
        smtp.quit()  # Terminate connection
        return True
    except (smtplib.SMTPException, TimeoutError, Exception) as e:
        return False  # Mark invalid if any exception occurs

def check_blacklist(domain):
    """Check if the domain is blacklisted."""
    # List of known blacklisted domains (can be expanded)
    blacklisted_domains = ['example.com', 'spam.com', 'trashmail.com']  # Example blacklist
    
    # Check if the domain is in the blacklisted list
    return domain in blacklisted_domains

def calculate_risk_score(smtp_verified, blacklisted):
    """Calculate risk score based on SMTP verification and blacklist status."""
    score = 0
    if smtp_verified:
        score += 50  # Add score if SMTP verification succeeds
    if not blacklisted:
        score += 30  # Add score if domain is not blacklisted
    return score

# For testing purposes, you can generate a batch of invalid emails and print them
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))  # This line should now work correctly
