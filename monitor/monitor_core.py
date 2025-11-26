# monitor/monitor_core.py
import threading
import os
import time
from storage.db import init_db, add_event
from utils.helpers import now_iso, read_json
from utils.emailer import send_email

# monitors (these should exist in monitor/)
from monitor.file_monitor import start_file_monitor, set_alert_callback
from monitor.proc_net_monitor import ProcNetMonitor
from monitor.net_monitor import NetMonitor
from config import MONITOR_PATHS

# load teacher username from assets/teacher_creds.json
CREDS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "teacher_creds.json")
def load_teacher():
    try:
        obj = read_json(CREDS_PATH, default={})
        return (obj.get("username") or "").strip()
    except Exception:
        return ""
TEACHER_USER = load_teacher()

def _safe_str(s):
    try:
        return (s or "").strip()
    except Exception:
        return ""

class HIDS:
    def __init__(self, email_alerts=True):
        init_db()
        self.email_alerts = email_alerts
        self.stop_event = threading.Event()
        # monitors
        self.proc_monitor = ProcNetMonitor()
        self.net_monitor = NetMonitor()
        self.file_observer = None
        self.threads = []

    def alert(self, event):
        """
        Centralized alert function:
        - Skips emailing for whitelisted teacher user (but logs the event)
        - Uses event-provided _rate_key/_rate_seconds if present, else constructs a stable key
        - Calls send_email(...) and logs outcome
        """
        try:
            subj = f"[mini-HIDS] {event.get('type')}"
            body = f"Detected event:\n{event}"
            etype = (event.get("type") or "event").strip()
            # preferred user fields from different monitors
            user = _safe_str(event.get("user") or event.get("user_entered") or event.get("owner"))

            # If event belongs to whitelisted teacher -> log & skip emailing
            if user and TEACHER_USER and user == TEACHER_USER:
                try:
                    add_event({"ts": now_iso(), "type": "alert_whitelisted_ignored", "user": user, "orig_event": event})
                except Exception:
                    pass
                return False

            if not self.email_alerts:
                try:
                    add_event({"ts": now_iso(), "type": "alert_email_disabled", "event": event})
                except Exception:
                    pass
                return False

            
            rate_key = event.get("_rate_key")
            rate_seconds = event.get("_rate_seconds")
            if rate_seconds is None:
                try:
                    rate_seconds = int(os.environ.get("MINI_HIDS_EMAIL_RATE_SECS", "300"))
                except Exception:
                    rate_seconds = 300

            
            if not rate_key:
                if etype.startswith("auth") or etype.startswith("gui"):
                    user_key = user or 'nouser'
                    rate_key = f"auth_{user_key}"
                elif etype.startswith("process") or "proc" in etype:
                    procname = (event.get("name") or event.get("procname") or "proc").replace(" ", "_")
                    owner = user or event.get("owner") or "noowner"
                    rate_key = f"proc_{procname}_{owner}"
                elif etype.startswith("net") or etype in ("suspicious_connection", "suspicious_listen"):
                    local = event.get("local") or "nlocal"
                    remote = event.get("remote") or "nremote"
                    rate_key = f"{etype}_{local}_{remote}"
                else:
                    rate_key = f"{etype}_{user or 'nouser'}_{event.get('ip') or event.get('pid') or 'norec'}"

            # attempt to send email using rate limiting
            try:
                sent = send_email(subj, body, rate_key=rate_key, rate_seconds=rate_seconds)
            except TypeError:
                # older send_email signature fallback (no rate args)
                sent = send_email(subj, body)

            # log result for auditing
            if sent:
                try:
                    add_event({"ts": now_iso(), "type": "email_sent", "subject": subj, "rate_key": rate_key})
                except Exception:
                    pass
            else:
                try:
                    add_event({"ts": now_iso(), "type": "email_rate_limited_or_failed", "rate_key": rate_key, "event_type": etype})
                except Exception:
                    pass

            return bool(sent)
        except Exception as e:
            try:
                add_event({"ts": now_iso(), "type": "email_failed_exception", "error": str(e), "event": event})
            except Exception:
                pass
            return False

    def start(self):
        # set file monitor to use our alert callback (file_monitor will call this)
        try:
            set_alert_callback(self.alert)
        except Exception:
            pass

        # start file observer
        try:
            self.file_observer = start_file_monitor(MONITOR_PATHS)
            add_event({"ts": now_iso(), "type": "file_monitor_started", "paths": MONITOR_PATHS})
        except Exception as e:
            add_event({"ts": now_iso(), "type": "file_monitor_start_failed", "error": str(e)})

        # start proc monitor thread
        try:
            t1 = threading.Thread(target=self.proc_monitor.run_loop, args=(self.stop_event, self.alert), daemon=True)
            t1.start()
            self.threads.append(t1)
            add_event({"ts": now_iso(), "type": "proc_monitor_started"})
        except Exception as e:
            add_event({"ts": now_iso(), "type": "proc_monitor_start_failed", "error": str(e)})

        # start net monitor thread
        try:
            t2 = threading.Thread(target=self.net_monitor.run_loop, args=(self.stop_event, self.alert), daemon=True)
            t2.start()
            self.threads.append(t2)
            add_event({"ts": now_iso(), "type": "net_monitor_started"})
        except Exception as e:
            add_event({"ts": now_iso(), "type": "net_monitor_start_failed", "error": str(e)})

    def stop(self):
        try:
            self.stop_event.set()
        except Exception:
            pass

        # stop file observer if any
        try:
            if self.file_observer:
                try:
                    self.file_observer.stop()
                except Exception:
                    pass
                try:
                    # watchdog observer has join()
                    self.file_observer.join(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass

        # join threads
        for t in self.threads:
            try:
                t.join(timeout=2)
            except Exception:
                pass

        add_event({"ts": now_iso(), "type": "hids_stopped"})

