import re
import dns.resolver
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# SMTP settings (test email sending)
SMTP_SERVER = "smtp.mailtrap.io"  # Replace with your SMTP server
SMTP_PORT = 587
SMTP_USER = "your_smtp_user"  # Your SMTP user
SMTP_PASSWORD = "your_smtp_password"  # Your SMTP password
SENDER_EMAIL = "test@yourdomain.com"  # Sender's email address (used for sending test emails)

def send_test_email(recipient_email):
    """Send a test email to the recipient to verify if it's valid."""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = 'Test Email for Verification'

        body = 'This is a test email for verification purposes.'
        msg.attach(MIMEText(body, 'plain'))

        # Set up SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()

        return True  # Email was sent successfully
    except smtplib.SMTPException as e:
        print(f"Error sending email to {recipient_email}: {str(e)}")
        return False  # Failed to send email

def is_valid_email(email):
    # Check email format with regex
    if not re.match(EMAIL_REGEX, email):
        return False

    # Extract domain from email
    domain = email.split('@')[-1]

    # Check DNS cache
    if domain in dns_cache:
        return dns_cache[domain]

    try:
        # Check if domain has MX records (Mail Exchange records) in DNS
        dns.resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        # NXDOMAIN: No such domain
        # NoAnswer: Domain exists, but no MX record
        # Timeout: DNS request failed
        dns_cache[domain] = False
        return False

    # After DNS check, send a test email to further validate the address
    if send_test_email(email):
        return True
    else:
        dns_cache[domain] = False
        return False

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    # Concurrently process emails using the ThreadPoolExecutor
    results = list(executor.map(is_valid_email, emails))

    # Filter valid emails based on the results
    valid_emails = [email for email, valid in zip(emails, results) if valid]
    
    # Return valid emails as a JSON response
    return jsonify({'validEmails': valid_emails})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
