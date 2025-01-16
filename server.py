import re
import dns.resolver
from flask import Flask, request, jsonify, render_template
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache
import os

app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = TTLCache(maxsize=1000, ttl=300)

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=10)

def is_valid_email(email):
    # Check email format
    if not re.match(EMAIL_REGEX, email):
        return False

    # Extract domain from email
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

# Route to serve index.html (home page)
@app.route('/')
def home():
    return render_template('index.html')  # This assumes index.html is in the templates folder

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    # Concurrently process emails
    results = list(executor.map(is_valid_email, emails))
    valid_emails = [email for email, valid in zip(emails, results) if valid]
    return jsonify({'validEmails': valid_emails})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
