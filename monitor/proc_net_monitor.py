# monitor/proc_net_monitor.py
"""
ProcNetMonitor - process monitor for mini_hids.

Features:
- Detects new processes using psutil
- Detects suspicious processes from rules.json
- Logs all events to encrypted DB
- Calls central alert() in monitor_core with proper rate_key to avoid multiple emails
"""

import os
import time
import threading

from utils.helpers import now_iso, read_json
from storage.db import add_event

try:
    import psutil
except Exception:
    psutil = None

# Paths
BASE_DIR = os.path.dirname(__file__)
RULES_PATH = os.path.join(BASE_DIR, "..", "rules.json")
CREDS_PATH = os.path.join(BASE_DIR, "..", "assets", "teacher_creds.json")

# -------------------------------------------------------
# Load suspicious process names
# -------------------------------------------------------
def _load_suspicious():
    try:
        rules = read_json(RULES_PATH, default={})
        return [x.lower() for x in rules.get("suspicious_processes", [])]
    except Exception:
        return []

SUSPICIOUS = _load_suspicious()


# -------------------------------------------------------
# Load teacher username
# -------------------------------------------------------
def _load_teacher():
    try:
        obj = read_json(CREDS_PATH, default={})
        u = obj.get("username") or ""
        return u.strip()
    except Exception:
        return ""

TEACHER_USER = _load_teacher()


# -------------------------------------------------------
# Build stable rate key (PREVENT MULTIPLE EMAILS)
# -------------------------------------------------------
def _proc_rate_key(name, user):
    """
    Every *unique* process name + user combination gets ONE email per cooldown.
    """
    name = (name or "proc").replace(" ", "_").lower()
    user = user or "nouser"
    return f"proc_{name}_{user}"


def _proc_rate_seconds():
    """
    Rate limit time for process alerts.
    Use MINI_HIDS_EMAIL_RATE_SECS or fallback to 600.
    """
    try:
        return int(os.environ.get("MINI_HIDS_EMAIL_RATE_SECS_PROCESS",
                                  os.environ.get("MINI_HIDS_EMAIL_RATE_SECS", "600")))
    except Exception:
        return 600


# -------------------------------------------------------
# Main monitor class
# -------------------------------------------------------
class ProcNetMonitor:
    def __init__(self, polling_interval=1.0):
        self.polling = float(polling_interval)
        self._prev_snapshot = {}

    def _snapshot(self):
        """Take snapshot of processes."""
        result = {}
        if psutil is None:
            return result

        try:
            for p in psutil.process_iter(['name', 'username']):
                try:
                    info = p.info
                    name = info.get("name") or ""
                    raw_user = info.get("username") or ""
                    user = raw_user.split("\\")[-1].split("/")[-1]
                    result[int(p.pid)] = (name, user)
                except Exception:
                    continue
        except Exception:
            return {}

        return result

    def _ev(self, etype, pid, name, user):
        """Create event dict with rate keys."""
        return {
            "ts": now_iso(),
            "type": etype,
            "pid": pid,
            "name": name,
            "user": user,
            "_rate_key": _proc_rate_key(name, user),
            "_rate_seconds": _proc_rate_seconds()
        }

    def run_loop(self, stop_event, alert_callback):
        """Main monitoring loop."""
        if psutil is None:
            add_event({"ts": now_iso(), "type": "proc_monitor_missing_psutil"})
            return

        try:
            self._prev_snapshot = self._snapshot()
        except Exception:
            self._prev_snapshot = {}

        while not stop_event.is_set():
            try:
                time.sleep(self.polling)
                cur = self._snapshot()

                new_pids = set(cur.keys()) - set(self._prev_snapshot.keys())
                for pid in sorted(new_pids):
                    name, user = cur.get(pid, ("", ""))

                    # Ignore teacher-owned processes
                    if user and user == TEACHER_USER:
                        add_event({
                            "ts": now_iso(),
                            "type": "process_ignored_teacher",
                            "pid": pid,
                            "name": name,
                            "user": user
                        })
                        continue

                    # Normal process_start
                    ev = self._ev("process_start", pid, name, user)
                    try:
                        add_event(ev)
                    except Exception:
                        pass

                    # Suspicious?
                    if name.lower() in SUSPICIOUS:
                        sev = self._ev("suspicious_process", pid, name, user)
                        try:
                            add_event(sev)
                        except Exception:
                            pass
                        try:
                            alert_callback(sev)
                        except Exception:
                            pass

                    # Normal process alert
                    else:
                        try:
                            alert_callback(ev)
                        except Exception:
                            pass

                self._prev_snapshot = cur

            except Exception as e:
                add_event({"ts": now_iso(), "type": "proc_monitor_error", "error": str(e)})
                time.sleep(1)

        add_event({"ts": now_iso(), "type": "proc_monitor_stopped"})

