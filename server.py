import re
import dns.resolver
import smtplib
from flask import Flask, request, jsonify
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

# SMTP server settings (use mail server IP or host)
SMTP_TIMEOUT = 10  # Timeout for SMTP connection

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
        # Use SMTP to check if email is valid
        if verify_smtp_email(email):
            return True
        else:
            dns_cache[domain] = False
            return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        dns_cache[domain] = False
        return False

def verify_smtp_email(email):
    domain = email.split('@')[-1]
    try:
        # Get the mail server for the domain (MX record lookup)
        mx_records = dns.resolver.resolve(domain, 'MX')
        mail_server = str(mx_records[0].exchange)

        # Connect to the mail server
        with smtplib.SMTP(mail_server, 25, timeout=SMTP_TIMEOUT) as server:
            server.set_debuglevel(0)  # Disable debug output

            # Try to connect and send a RCPT TO command
            server.helo()  # Say hello to the server
            server.mail('example@domain.com')  # Sender email (dummy sender)
            code, message = server.rcpt(email)  # Try to check recipient

            # If 250 response code is returned, the email is valid
            if code == 250:
                return True
            else:
                return False
    except (smtplib.SMTPException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
        print(f"SMTP validation failed for {email}: {str(e)}")
        return False

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

