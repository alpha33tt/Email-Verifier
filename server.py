from flask import Flask, render_template, request, jsonify
import os
import re
import dns.resolver
import smtplib
from email.utils import parseaddr
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache

app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = TTLCache(maxsize=1000, ttl=300)

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=10)

@app.route('/')
def index():
    return render_template('index.html')  # Render the HTML page from the templates folder

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    # Concurrently process emails to validate email format
    results = list(executor.map(is_valid_email, emails))
    valid_emails = [email for email, valid in zip(emails, results) if valid]

    # Check bounce results for valid emails
    bounce_results = {}
    for email in valid_emails:
        bounce_result = smtp_check(email)
        bounce_results[email] = bounce_result

    return jsonify({'validEmails': valid_emails, 'bounceResults': bounce_results})

def is_valid_email(email):
    # Check email format using regex
    if not re.match(EMAIL_REGEX, email):
        return False

    # Extract domain from email
    domain = email.split('@')[-1]

    # Check DNS cache for MX records
    if domain in dns_cache:
        return dns_cache[domain]

    try:
        # Check if the domain has MX records in DNS
        dns.resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        dns_cache[domain] = False
        return False

def smtp_check(email):
    """Verify the email's SMTP server to check for bounce-backs."""
    try:
        domain = email.split('@')[1]
        # Connect to the SMTP server
        server = smtplib.SMTP(domain, timeout=10)
        server.set_debuglevel(0)  # Disable debug output
        server.helo()

        # Perform a simple SMTP MAIL FROM command to check validity
        status, message = server.mail(parseaddr(email)[1])

        server.quit()

        if status == 250:
            return "Valid"
        else:
            return "Invalid"
    except Exception as e:
        print(f"SMTP error for {email}: {e}")
        return "Invalid"

# For testing purposes, you can generate a batch of invalid emails and print them
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))  # This line should now work correctly
