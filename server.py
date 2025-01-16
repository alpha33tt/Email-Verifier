import re
import dns.resolver
import os
import aiodns
import asyncio
from flask import Flask, render_template, request, jsonify
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache
import smtplib
from email.utils import parseaddr

app = Flask(__name__)

# Regular expression for email validation
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# List of disposable email domains (for quick checking)
DISPOSABLE_DOMAINS = {"mailinator.com", "guerrillamail.com", "temp-mail.org", "10minutemail.com", "yopmail.com"}

# Cache for DNS lookups (TTL: 300 seconds, max size: 1000 entries)
dns_cache = TTLCache(maxsize=1000, ttl=300)

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=50)

# Asynchronous DNS resolver
resolver = aiodns.DnsResolver()

# SMTP check function (basic example)
def smtp_check(email):
    try:
        domain = email.split('@')[1]
        # Perform basic SMTP handshake (this is simplified and may not work for all servers)
        server = smtplib.SMTP(domain)
        server.set_debuglevel(0)  # 0 means no debug output
        server.helo()
        status, message = server.mail(parseaddr(email)[1])
        server.quit()
        if status == 250:
            return True
        else:
            return False
    except Exception as e:
        print(f"SMTP error for {email}: {e}")
        return False

# Function to check if an email is from a disposable domain
def is_disposable_email(email):
    domain = email.split('@')[1]
    return domain in DISPOSABLE_DOMAINS

async def is_valid_email_async(email):
    # Check email format
    if not re.match(EMAIL_REGEX, email):
        return False

    # Check if the email is from a disposable domain
    if is_disposable_email(email):
        return False

    # Extract domain from email
    domain = email.split('@')[-1]

    # Check DNS cache
    if domain in dns_cache:
        return dns_cache[domain]

    try:
        # Check if domain has MX records
        await resolver.resolve(domain, 'MX')
        dns_cache[domain] = True
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        dns_cache[domain] = False
        return False

def is_valid_email(email):
    # Async wrapper for email validation
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(is_valid_email_async(email))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_emails():
    data = request.get_json()
    emails = data.get('emails', [])

    # Concurrently process emails
    results = list(executor.map(is_valid_email, emails))

    # Filter valid emails
    valid_emails = [email for email, valid in zip(emails, results) if valid]

    # Optional: Check bouncebacks (SMTP check) for valid emails
    email_bounce_results = {email: smtp_check(email) for email in valid_emails}

    return jsonify({
        'validEmails': valid_emails,
        'emailBounceResults': email_bounce_results
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
