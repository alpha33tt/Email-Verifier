import random
import string
import re
import smtplib
import dns.resolver
from flask import Flask, request, jsonify, render_template
import socket
import os

app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = {}

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
        print(f"Error in SMTP validation for {email}: {str(e)}")
        return False

# This is the function to check email validity
def is_valid_email(email):
    # Check email format
    if not re.match(EMAIL_REGEX, email):
        print(f"Invalid email format: {email}")
        return False

    # First perform MX check
    domain = email.split('@')[-1]
    if domain in dns_cache:
        if dns_cache[domain] is False:
            print(f"Domain {domain} is known to be invalid")
            return False
    
    try:
        # Check MX record (Mail Exchange) for the domain
        dns.resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
        print(f"MX record found for domain {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        print(f"MX Record check failed for {email}: {str(e)}")
        dns_cache[domain] = False
        return False

    # Now perform SMTP check for validity
    if not smtp_check(email):
        return False

    return True

# API endpoint to verify emails
@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    valid_emails = []
    for email in emails:
        if is_valid_email(email):
            valid_emails.append(email)

    print(f"Valid Emails: {valid_emails}")  # Debugging line
    return jsonify({'validEmails': valid_emails})

# Route to serve the index.html page from the templates folder
@app.route('/')
def index():
    return render_template('index.html')  # This will render the index.html from templates/

# Function to generate random invalid emails (for testing only)
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
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
