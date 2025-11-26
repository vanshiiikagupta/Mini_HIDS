from utils.emailer import send_email
from storage.db import add_event
from utils.helpers import now_iso

TRUSTED_USER = "teacher"        # allowed username
TRUSTED_PASSWORD = "teacher123" # allowed password

class AuthMonitor:
    def __init__(self):
        pass

    def check_login(self, username, password, source_ip="127.0.0.1"):
        """Check login attempts and trigger alerts."""

        ts = now_iso()

        # Wrong username 
        if username != TRUSTED_USER:
            add_event({"ts": ts, "type": "login_failed", "reason": "unknown_user", "user": username})
            send_email(
                "ALERT: Unknown Username Login Attempt",
                f"Suspicious login attempt detected.\n"
                f"User: {username}\n"
                f"Password Entered: {password}\n"
                f"IP: {source_ip}\n"
                f"Time: {ts}",
                rate_key="unknown_user_alert",
                rate_seconds=20
            )
            return False

        #Wrong password
        if password != TRUSTED_PASSWORD:
            add_event({"ts": ts, "type": "login_failed", "reason": "wrong_password", "user": username})
            send_email(
                "ALERT: Wrong Password Attempt",
                f"User: {username}\n"
                f"Wrong password entered: {password}\n"
                f"IP: {source_ip}\n"
                f"Time: {ts}",
                rate_key="wrong_password_alert",
                rate_seconds=20
            )
            return False

        #Suspicious login even for correct user
        if source_ip not in ["127.0.0.1", "localhost"]:
            add_event({"ts": ts, "type": "login_suspicious_ip", "user": username, "ip": source_ip})
            send_email(
                "ALERT: Suspicious Login IP",
                f"User: {username}\n"
                f"Logged in from: {source_ip}\n"
                f"Time: {ts}",
                rate_key="ip_alert",
                rate_seconds=20
            )

        # Trusted teacher login (NO EMAIL)
        add_event({"ts": ts, "type": "login_success", "user": username})
        return True

