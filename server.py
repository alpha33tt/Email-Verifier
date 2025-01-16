from flask import Flask, render_template, request, jsonify
import uuid
import dns.resolver  # For MX record checking
import smtplib       # For SMTP verification
import os            # Don't forget to import 'os'

app = Flask(__name__)

# In-memory storage for simplicity
api_keys = {}
daily_limit = 1000

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

    for email in emails:
        result = validate_email(email)
        if result["valid"]:
            valid_emails.append(result)
        else:
            invalid_emails.append(email)

    api_keys[api_key]["used_today"] += len(emails)

    return jsonify({"valid": valid_emails, "invalid": invalid_emails})

def validate_email(email):
    """Validate email using MX record and SMTP."""
    try:
        # Check MX record
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)

        # Verify with SMTP (optional)
        smtp_verified = False
        try:
            smtp = smtplib.SMTP(mx_record)
            smtp.starttls()
            smtp.quit()
            smtp_verified = True
        except Exception:
            smtp_verified = False

        return {
            "email": email,
            "valid": True,
            "mx_record": mx_record,
            "smtp_verified": smtp_verified,
            "no_bounce": True  # Placeholder, implement bounce check if needed
        }
    except Exception:
        return {"email": email, "valid": False}

# For testing purposes, you can generate a batch of invalid emails and print them
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))  # This line should now work correctly
