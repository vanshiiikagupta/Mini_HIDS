import os
import smtplib
from email.mime.text import MIMEText
from storage.db import add_event
from utils.helpers import now_iso

SMTP_USER = os.getenv("MINI_HIDS_SMTP_USER")
SMTP_PASS = os.getenv("MINI_HIDS_SMTP_PASS")
FROM_ADDR = os.getenv("MINI_HIDS_FROM_ADDR")
TO_ADDRS = os.getenv("MINI_HIDS_TO_ADDRS", "").split(",")

RATE_LIMIT = {}  # {key: last_sent_timestamp}

def send_email(subject, body, rate_key=None, rate_seconds=30):
    """Real email sender with rate limiting."""

    # sanity check
    if not SMTP_USER or not SMTP_PASS or not FROM_ADDR or not TO_ADDRS:
        add_event({
            "ts": now_iso(),
            "type": "email_error",
            "reason": "Missing SMTP environment variables"
        })
        return False

    # rate limiting
    import time
    if rate_key:
        last = RATE_LIMIT.get(rate_key, 0)
        if time.time() - last < rate_seconds:
            return True
        RATE_LIMIT[rate_key] = time.time()

    # build email
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = FROM_ADDR
    msg["To"] = ", ".join(TO_ADDRS)

    try:
        # Gmail SMTP
        s = smtplib.SMTP("smtp.gmail.com", 587)
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(FROM_ADDR, TO_ADDRS, msg.as_string())
        s.quit()

        add_event({"ts": now_iso(), "type":"email_sent", "subject": subject})
        return True

    except Exception as e:
        add_event({
            "ts": now_iso(),
            "type": "email_error",
            "subject": subject,
            "error": str(e)
        })
        return False

