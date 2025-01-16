import re
import dns.resolver
from flask import Flask, request, jsonify, render_template
from concurrent.futures import ThreadPoolExecutor, as_completed
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

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    if len(emails) > 2000:
        return jsonify({"error": "Too many emails, please verify in smaller batches."}), 400

    # List to store results
    valid_emails = []

    # Break emails into batches of 200 or less
    batch_size = 200
    batches = [emails[i:i + batch_size] for i in range(0, len(emails), batch_size)]

    # Process each batch concurrently
    futures = []
    for batch in batches:
        future = executor.submit(process_batch, batch)
        futures.append(future)

    # Collect results from all futures
    for future in as_completed(futures):
        valid_emails.extend(future.result())

    return jsonify({'validEmails': valid_emails})

def process_batch(batch):
    results = [email for email in batch if is_valid_email(email)]
    return results

# Route to serve the index.html page from the templates folder
@app.route('/')
def index():
    return render_template('index.html')  # This will render the index.html from templates/

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
