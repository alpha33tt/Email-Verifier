import re
import dns.resolver
import requests
import os
from email.utils import parseaddr
from flask import Flask, render_template, request, jsonify
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache

# Initialize Flask app
app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = TTLCache(maxsize=1000, ttl=300)

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=50)

# Email Hippo (basic usage, no API key required)
EMAIL_HIPPO_API_URL = 'https://api.emailhippo.com/v1/emailverify'  # Ensure the URL is correct for your use case

# Function to check email format
def is_valid_email_format(email):
    if not re.match(EMAIL_REGEX, email):
        return False
    return True

# Function to validate email using Email Hippo API (no API key required)
def validate_email_with_hippo(email):
    response = requests.post(EMAIL_HIPPO_API_URL, json={'email': email})
    result = response.json()

    # Check the response for the verification status
    if 'status' in result and result['status'] == 'valid':
        return True
    return False

# Function to check if an email is from a disposable domain
DISPOSABLE_DOMAINS = {"mailinator.com", "guerrillamail.com", "temp-mail.org", "10minutemail.com", "yopmail.com"}

def is_disposable_email(email):
    domain = email.split('@')[1]
    return domain in DISPOSABLE_DOMAINS

# Function to check if email domain has MX records (synchronous DNS lookup)
def is_valid_email_domain(email):
    domain = email.split('@')[-1]
    
    # Check DNS cache
    if domain in dns_cache:
        return dns_cache[domain]
    
    try:
        # Check if domain has MX records
        dns.resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        dns_cache[domain] = False
        return False

# SMTP check function (basic example)
def smtp_check(email):
    try:
        domain = email.split('@')[1]
        # Perform basic SMTP handshake (simplified)
        server = smtplib.SMTP(domain)
        server.set_debuglevel(0)
        server.helo()
        status, message = server.mail(parseaddr(email)[1])
        server.quit()
        if status == 250:
            return True
        return False
    except Exception as e:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    # Concurrently process emails using both your DNS check and Email Hippo verification
    results = list(executor.map(is_valid_email_format, emails))

    valid_emails = [email for email, valid in zip(emails, results) if valid]

    # Optionally, further verify emails using Email Hippo API
    email_hippo_valid_emails = [email for email in valid_emails if validate_email_with_hippo(email)]
    
    # Optional: Check bouncebacks (SMTP check) for valid emails
    email_bounce_results = {email: smtp_check(email) for email in email_hippo_valid_emails}

    return jsonify({
        'validEmails': email_hippo_valid_emails,
        'emailBounceResults': email_bounce_results
    })

# Main execution
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
