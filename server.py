from flask import Flask, render_template, request, jsonify
import uuid
import dns.asyncresolver  # Async DNS resolver
import smtplib
import os
import re
import jwt
import datetime
import asyncio
from secrets import token_urlsafe
import aiohttp  # For async HTTP requests if needed

app = Flask(__name__)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random, secure key

# In-memory storage for simplicity
api_keys = {}
daily_limit = 1000

# Route for the API Key generation page
@app.route("/")
async def index():
    return render_template("index.html")

# API endpoint to generate an API key (JWT)
@app.route("/generate-api-key", methods=["POST"])
async def generate_api_key():
    # Generate a secure token
    api_key = token_urlsafe(32)  # Strong API key generation
    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # 1 day expiration

    # Encode the JWT with expiration and key
    token = jwt.encode({'api_key': api_key, 'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
    api_keys[api_key] = {"used_today": 0}
    return jsonify({"api_key": token})

# Route for the Email Validation page
@app.route("/verify")
async def verify_page():
    return render_template("verify.html")

# API endpoint to validate emails
@app.route("/api/verify", methods=["POST"])
async def verify_emails():
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

    data = await request.json
    emails = data.get("emails", [])
    valid_emails = []
    invalid_emails = []

    # Use async to validate emails concurrently
    tasks = [validate_single_email(email) for email in emails]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result["valid"]:
            valid_emails.append(result)
        else:
            invalid_emails.append(result["email"])

    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})

async def validate_single_email(email):
    """Validates a single email address."""
    result = {"email": email}
    try:
        # Syntax Check
        if not is_valid_email_syntax(email):
            result["valid"] = False
            result["error"] = "Invalid email syntax"
            return result

        # MX Record Lookup (async version)
        domain = email.split('@')[1]
        mx_records = await resolve_mx(domain)
        if not mx_records:
            result["valid"] = False
            result["error"] = "No MX records found"
            return result
        mx_record = str(mx_records[0].exchange)

        # SMTP Verification (optional, but recommended) - async
        smtp_verified = await verify_smtp(mx_record)
        if not smtp_verified:
            result["valid"] = False
            result["error"] = "SMTP verification failed"
            return result

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

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    return result

def is_valid_email_syntax(email):
    """Check the basic syntax of an email address."""
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(regex, email))

async def resolve_mx(domain):
    """Asynchronous MX record lookup using `dns.asyncresolver`."""
    try:
        mx_records = await dns.asyncresolver.resolve(domain, 'MX')
        return mx_records
    except dns.exception.DNSException:
        return None

async def verify_smtp(mx_record):
    """Asynchronous SMTP verification."""
    try:
        reader, writer = await asyncio.open_connection(mx_record, 25)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
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

# For testing purposes, you can generate a batch of invalid emails and print them
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))  # This line should now work correctly
