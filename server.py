import random
import string
import re
import smtplib
import dns.resolver
from flask import Flask, request, jsonify, render_template
from concurrent.futures import ThreadPoolExecutor, as_completed
from cachetools import TTLCache
import os
import socket
import time

app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zAHZ0-9.-]+\.[a-zA-Z]{2,}$"

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = TTLCache(maxsize=1000, ttl=300)

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=10)

# This function performs an SMTP check to verify the email address
def smtp_check(email):
    domain = email.split('@')[-1]

    try:
        # Check MX records to find the mail server
        answers = dns.resolver.resolve(domain, 'MX')
        mx_record = str(answers[0].exchange)

        # Create an SMTP connection with a timeout
        with smtplib.SMTP(mx_record, timeout=10) as server:
            server.set_debuglevel(0)  # Turn off debug output
            server.helo()  # Greet the server
            server.mail('me@domain.com')  # The sender (can be anything)
            code, message = server.rcpt(email)  # Try to send to the recipient

            # If the server returns a success code (250), the email is valid
            if code == 250:
                return True
            else:
                print(f"SMTP validation failed for {email}: {message}")
                return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, smtplib.SMTPException, socket.timeout, Exception) as e:
        # In case of DNS lookup failure, SMTP errors, or timeouts, consider the email invalid
        print(f"Error in SMTP validation for {email}: {str(e)}")
        return False

# This is the function to check email validity
def is_valid_email(email):
    # Check email format
    if not re.match(EMAIL_REGEX, email):
        print(f"Invalid email format: {email}")
        return False

    # First perform SMTP check for validity
    if not smtp_check(email):
        return False

    # Check DNS cache to avoid redundant queries
    domain = email.split('@')[-1]
    if domain in dns_cache:
        return dns_cache[domain]

    try:
        # Check MX record (Mail Exchange) for the domain
        dns.resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        print(f"MX Record check failed for {email}: {str(e)}")
        dns_cache[domain] = False
        return False

# API endpoint to verify emails
@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    if len(emails) > 2000:
        return jsonify({"error": "Too many emails, please verify in smaller batches."}), 400

    # List to store valid results
    valid_emails = []

    # Break emails into batches of 200 or less
    batch_size = 100  # A smaller batch size to speed up processing
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

# Function to generate random invalid emails
def generate_invalid_emails(num_emails=10):
    invalid_emails = []
    fake_domains = ["example.fake", "nonexistent.domain", "test.invalid", "random123.xyz", "noexists.com"]
    
    for _ in range(num_emails):
        prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))  # Random prefix
        domain = random.choice(fake_domains)  # Random invalid domain
        invalid_emails.append(f"{prefix}@{domain}")
    
    return invalid_emails

# For testing purposes, you can generate a batch of invalid emails and print them
if __name__ == '__main__':
    # Generate random invalid emails (for testing only)
    invalid_emails = generate_invalid_emails(10)  # You can change the number here
    print("Generated invalid emails:", invalid_emails)
    
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
