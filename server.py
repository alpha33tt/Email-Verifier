from flask import Flask, render_template, request, jsonify
import uuid
import dns.resolver  # For MX record checking
import smtplib       # For SMTP verification
import os            # Don't forget to import 'os'
from concurrent.futures import ThreadPoolExecutor
import re            # For syntax checking of emails

app = Flask(__name__)

# In-memory storage for simplicity
api_keys = {}
daily_limit = 1000

# Setup ThreadPoolExecutor to parallelize email validation tasks
executor = ThreadPoolExecutor(max_workers=10)  # Adjust the number of concurrent tasks

# Route for the API Key generation page
@app.route("/")
def index():
    return render_template("index.html")

# API endpoint to generate an API key
@app.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    api_key = str(uuid.uuid4())  # Generate a unique API key
    api_keys[api_key] = {"used_today": 0}
    return jsonify({"api_key": api_key})

# Route for the Email Validation page
@app.route("/verify")
def verify_page():
    return render_template("verify.html")

# API endpoint to validate emails
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

        # SMTP Verification (optional, but recommended)
        smtp_verified = verify_smtp(mx_record)

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

def verify_smtp(mx_record):
    """Verify SMTP for the domain (simplified version)."""
    try:
        smtp = smtplib.SMTP(mx_record)
        smtp.set_debuglevel(0)
        smtp.quit()
        return True
    except Exception:
        return False

def check_blacklist(domain):
    """Dummy blacklist check. This should be replaced with a real blacklist API."""
    # For demonstration, consider 'example.com' as blacklisted.
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
