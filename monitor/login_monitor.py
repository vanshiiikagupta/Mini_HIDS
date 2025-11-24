# monitor/login_monitor.py (fixed)
import time
import threading
import re
import os
import json
from storage.db import add_event
from utils.helpers import now_iso, read_json

# Patterns (tail /var/log/auth.log)
AUTH_LOG = "/var/log/auth.log"

FAILED_PW_RE = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_PW_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
SUDO_FAIL_RE = re.compile(r"sudo: .*authentication failure; .*")
SUDO_OK_RE = re.compile(r"sudo: .*session opened for user (?P<user>\S+)")

CREDS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "teacher_creds.json")

def load_whitelist():
    try:
        creds = read_json(CREDS_PATH, default={})
        t = creds.get("username") or ""
        return {t.strip()} if t else set()
    except Exception:
        return set()

WHITELIST_USERS = load_whitelist()

def _is_whitelisted(user):
    if not user:
        return False
    return user.strip() in WHITELIST_USERS

def sanitize_str(s: str) -> str:
    """Make a short stable key-friendly string from user/ip."""
    if not s:
        return ""
    return "".join(c for c in s if c.isalnum() or c in ("_", "-")).lower()

class AuthTailer:
    """
    Tails /var/log/auth.log and creates auth events.
    Use: AuthTailer().start()  (set_alert_callback to let HIDS alert)
    """
    def __init__(self, path=AUTH_LOG, polling=1.0):
        self.path = path
        self.polling = float(polling)
        self._stop = threading.Event()
        self._t = None
        self.alert_callback = None

    def set_alert_callback(self, cb):
        self.alert_callback = cb

    def _process_line(self, line):
        ev = None
        m = FAILED_PW_RE.search(line)
        if m:
            ev = {"ts": now_iso(), "type": "auth_failed", "user": m.group("user").strip(), "ip": m.group("ip"), "raw": line.strip()}
        else:
            m = INVALID_USER_RE.search(line)
            if m:
                ev = {"ts": now_iso(), "type": "auth_invalid_user", "user": m.group("user").strip(), "ip": m.group("ip"), "raw": line.strip()}
            else:
                m = ACCEPTED_PW_RE.search(line)
                if m:
                    ev = {"ts": now_iso(), "type": "auth_success", "user": m.group("user").strip(), "ip": m.group("ip"), "raw": line.strip()}
                else:
                    m = SUDO_FAIL_RE.search(line)
                    if m:
                        ev = {"ts": now_iso(), "type": "sudo_failed", "raw": line.strip()}
                    else:
                        m = SUDO_OK_RE.search(line)
                        if m:
                            ev = {"ts": now_iso(), "type": "sudo_ok", "user": m.group("user").strip(), "raw": line.strip()}

        if not ev:
            return None

        # persist event to DB (encrypted)
        try:
            add_event(ev)
        except Exception:
            pass

        # If whitelisted user, still log but don't call alert to send email
        user = ev.get("user") or ""
        if _is_whitelisted(user):
            try:
                add_event({"ts": now_iso(), "type": "auth_whitelisted_ignored", "user": user, "raw": line.strip()})
            except Exception:
                pass
            return ev

        # call central alert callback if set
        try:
            if self.alert_callback:
                # stable rate_key per event type + user + ip
                safe_user = sanitize_str(user) or "nouser"
                safe_ip = sanitize_str(ev.get("ip") or "noip")
                rate_key = f"{ev.get('type')}_{safe_user}_{safe_ip}"
                ev["_rate_key"] = rate_key
                # also attach a suggested cooldown (can be honored by alert handler)
                ev["_rate_seconds"] = int(os.environ.get("MINI_HIDS_EMAIL_RATE_SECS", "300"))
                self.alert_callback(ev)
        except Exception as e:
            try:
                add_event({"ts": now_iso(), "type": "auth_alert_callback_failed", "error": str(e), "event": ev})
            except Exception:
                pass
        return ev

    def _tail_loop(self):
        try:
            # ensure file exists
            if not os.path.exists(self.path):
                add_event({"ts": now_iso(), "type": "auth_log_missing", "path": self.path})
                return

            with open(self.path, "r", errors="ignore") as f:
                # go to EOF initially
                f.seek(0, 2)
                while not self._stop.is_set():
                    where = f.tell()
                    line = f.readline()
                    if not line:
                        time.sleep(self.polling)
                        f.seek(where)
                    else:
                        self._process_line(line)
        except Exception as e:
            try:
                add_event({"ts": now_iso(), "type": "auth_monitor_error", "error": str(e)})
            except Exception:
                pass
            return

    def start(self):
        self._t = threading.Thread(target=self._tail_loop, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join(timeout=2)

