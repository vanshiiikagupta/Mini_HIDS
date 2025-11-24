#!/usr/bin/env python3
"""
start_hids.py

Lightweight launcher for mini_hids that:
 - starts monitors (file, proc, net)
 - avoids email spam by only sending emails for a small set of important event types
 - respects the teacher whitelist from assets/teacher_creds.json
 - respects MINI_HIDS_EMAIL_RATE_SECS (cooldown) from environment
 - runs in foreground and stops cleanly on Ctrl+C
"""

import os
import signal
import threading
import time
from storage.db import init_db, add_event
from utils.helpers import now_iso, read_json

# Load HIDS implementation (monitor_core.HIDS)
from monitor.monitor_core import HIDS

# Default cooldown (seconds) if env var not set
DEFAULT_EMAIL_RATE_SECS = int(os.environ.get("MINI_HIDS_EMAIL_RATE_SECS", "300"))
os.environ.setdefault("MINI_HIDS_EMAIL_RATE_SECS", str(DEFAULT_EMAIL_RATE_SECS))

# Which event types should trigger *emails* (others will be logged only).
# Keep this conservative to avoid spam during demo.
EMAIL_EVENT_WHITELIST = {
    "auth_failed",
    "auth_invalid_user",
    "sudo_failed",
    "gui_login_attempt",      # GUI login attempts (if you use GUI)
    "suspicious_process",
    "suspicious_connection",
    "suspicious_listen",
    "file_created",
    "file_modified",
    "file_deleted",
    # Add any other high-priority types you want emailed
}

# Load configured teacher username (so we can avoid emailing for teacher)
CREDS_PATH = os.path.join(os.path.dirname(__file__), "assets", "teacher_creds.json")
def load_teacher_user():
    try:
        obj = read_json(CREDS_PATH, default={})
        return (obj.get("username") or "").strip()
    except Exception:
        return ""

TEACHER_USER = load_teacher_user()

def is_high_priority_event(ev: dict) -> bool:
    """Return True if this event should cause an email (subject to rate-limiting)."""
    et = (ev.get("type") or "").strip()
    if not et:
        return False
    # If event is file_* allow only the three names
    if et.startswith("file_"):
        return et in ("file_created", "file_modified", "file_deleted")
    return et in EMAIL_EVENT_WHITELIST

def is_teacher_event(ev: dict) -> bool:
    """Return True if this event belongs to the teacher user (so we skip emailing)."""
    if not TEACHER_USER:
        return False
    user = (ev.get("user") or ev.get("user_entered") or ev.get("owner") or "").strip()
    return bool(user and user == TEACHER_USER)

def print_alert_block(ev: dict):
    print("\n=== ALERT (live) ===")
    print(ev)
    print("====================\n")

def main():
    print("Initializing DB and HIDS...")
    init_db()

    # instantiate HIDS (it will initialize monitors but we'll call start())
    h = HIDS(email_alerts=True)

    # wrap the HIDS.alert to implement our conservative emailing policy
    orig_alert = h.alert

    def guarded_alert(ev: dict):
        """Guard that logs, prints and only calls orig_alert for high-priority, non-teacher events."""
        # always persist the fact we saw an event (monitors also add_event themselves, but extra logging is okay)
        try:
            add_event({"ts": now_iso(), "type": "alert_received", "event_type": ev.get("type"), "meta": {"from": "start_hids_guard"}})
        except Exception:
            pass

        # print to console for demo
        print_alert_block(ev)

        # Whitelist: if teacher => log and skip emailing
        if is_teacher_event(ev):
            add_event({"ts": now_iso(), "type": "alert_whitelisted_ignored", "user": (ev.get("user") or ev.get("user_entered") or ""), "orig_event": ev})
            return False

        # Only trigger emails for high-priority events
        if not is_high_priority_event(ev):
            add_event({"ts": now_iso(), "type": "alert_filtered_out", "event": ev})
            return False

        # For allowed types, pass to original alert (it handles rate-keys / sending)
        try:
            return orig_alert(ev)
        except Exception as e:
            add_event({"ts": now_iso(), "type": "alert_send_exception", "error": str(e), "event": ev})
            print("Error while sending alert:", e)
            return False

    # monkeypatch
    h.alert = guarded_alert

    # Start HIDS monitors
    print("Starting monitors (file, proc & net). Press Ctrl+C to stop.")
    try:
        h.start()
    except Exception as e:
        print("Failed to start HIDS monitors:", e)
        add_event({"ts": now_iso(), "type": "hids_start_failed", "error": str(e)})
        return

    # handle signals so Ctrl+C stops gracefully
    stop_event = threading.Event()
    def _stop(signum=None, frame=None):
        print("\nStopping HIDS...")
        stop_event.set()
        try:
            h.stop()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # keep alive until stopped
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _stop()

    print("HIDS stopped. Bye.")

if __name__ == "__main__":
    main()

