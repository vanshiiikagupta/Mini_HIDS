#!/usr/bin/env python3
# tools/simulate_attacks.py
"""
Single demo script:
 - injects suspicious GUI login attempts (non-teacher) -> sends email
 - creates/modifies/deletes a demo file under ~/Desktop -> sends email
 - optionally starts a short nc listener to emulate suspicious process/port -> sends email
 - prints recent relevant DB log entries (login/auth/email/file/process)
"""
import os
import sys
import time
import subprocess
from datetime import datetime

# make project imports work regardless of current working directory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# project API (these names are used throughout the repo)
from storage.db import add_event, get_events  # add_event(ts,type,...) used earlier in project
from utils.helpers import now_iso
from utils.emailer import send_email

# try to load teacher username if monitor/monitor_core.py provides loader
TEACHER_USER = None
try:
    from monitor.monitor_core import load_teacher
    TEACHER_USER = load_teacher()
except Exception:
    TEACHER_USER = None

def ts():
    return now_iso()

def send_alert_for_event(subject, body, rate_key=None):
    """Call the project's emailer and also record an email_* event (add_event will store)."""
    ok = send_email(subject, body, rate_key=rate_key)
    # email send will itself add db events in your utils/emailer, but we add a trace too
    ev = {"ts": ts(), "type": "email_manual_send", "subject": subject, "ok": bool(ok)}
    add_event(ev)
    return ok

def simulate_login_attempts(usernames=("attacker","unknown")):
    print("\n--- Simulating login attempts ---")
    for u in usernames:
        ev = {"ts": ts(), "type":"gui_login_attempt", "user_entered": u, "result":"failed", "source":"simulator"}
        add_event(ev)
        print("Inserted:", ev)
        # send email only if not teacher and username non-empty
        teacher = (TEACHER_USER or "").strip()
        if u and (u != teacher):
            subj = f"[mini-HIDS] ALERT: Suspicious GUI login attempt by '{u}'"
            body = f"Detected simulated GUI login attempt:\n{ev}\nTime: {ts()}"
            rk = f"auth_{u}"
            ok = send_alert_for_event(subj, body, rate_key=rk)
            print("  -> email send returned:", ok)
        time.sleep(0.4)

def simulate_file_events():
    print("\n--- Simulating file create/modify/delete on Desktop ---")
    demo_path = os.path.expanduser("~/Desktop/mini_hids_demo_file.txt")
    # create
    open(demo_path, "w").write("mini hids demo\n")
    ev = {"ts": ts(), "type":"file_create", "path": demo_path, "source":"simulator"}
    add_event(ev)
    print("Inserted:", ev)
    subj = f"[mini-HIDS] ALERT: file_create {os.path.basename(demo_path)}"
    body = f"File created: {demo_path}\nEvent: {ev}"
    send_alert_for_event(subj, body, rate_key=f"file_{os.path.basename(demo_path)}")
    time.sleep(0.7)

    # modify
    with open(demo_path, "a") as f:
        f.write("modify line\n")
    ev = {"ts": ts(), "type":"file_modify", "path": demo_path, "source":"simulator"}
    add_event(ev)
    print("Inserted:", ev)
    subj = f"[mini-HIDS] ALERT: file_modify {os.path.basename(demo_path)}"
    body = f"File modified: {demo_path}\nEvent: {ev}"
    send_alert_for_event(subj, body, rate_key=f"file_{os.path.basename(demo_path)}")
    time.sleep(0.7)

    # delete
    try:
        os.remove(demo_path)
        ev = {"ts": ts(), "type":"file_delete", "path": demo_path, "source":"simulator"}
        add_event(ev)
        print("Inserted:", ev)
        subj = f"[mini-HIDS] ALERT: file_delete {os.path.basename(demo_path)}"
        body = f"File deleted: {demo_path}\nEvent: {ev}"
        send_alert_for_event(subj, body, rate_key=f"file_{os.path.basename(demo_path)}")
    except Exception as e:
        print("Could not delete demo file:", e)

def simulate_net_process():
    print("\n--- Simulating suspicious process / listening port (nc) ---")
    # attempt to spawn nc -l 9999 for a short time if nc exists
    if subprocess.call(["which", "nc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        try:
            p = subprocess.Popen(["nc", "-l", "9999"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)  # let it start
            ev = {"ts": ts(), "type":"process_start", "exe":"nc", "pid": p.pid, "source":"simulator"}
            add_event(ev)
            print("Inserted:", ev)
            subj = f"[mini-HIDS] ALERT: suspicious process started (nc pid={p.pid})"
            body = f"Suspicious process started (simulator): nc pid={p.pid}\nEvent: {ev}"
            send_alert_for_event(subj, body, rate_key=f"proc_nc_{p.pid}")
        finally:
            p.terminate()
            p.wait(timeout=3)
            print("Terminated nc (pid {})".format(ev.get("pid")))
    else:
        print("nc not installed; skipping real process simulation (you can install netcat-openbsd).")

def show_recent_logs(limit=80):
    print("\n=== RECENT SUSPICIOUS/EVENT LOGS (filtered) ===")
    rows = get_events(limit)
    # print only relevant types
    interesting = ("gui_login_attempt","file_create","file_modify","file_delete","process_start",
                   "email_sent","email_failed","email_manual_send","auth_failed","auth_invalid_user","sudo_failed")
    for id_, ts_str, ev in rows[-limit:]:
        if ev.get("type") in interesting or ev.get("type","").startswith("email_"):
            print(id_, ts_str, ev)

def main():
    print("Starting combined simulation (will inject events + send emails).")
    print("Make sure you exported SMTP env vars before running, e.g.:")
    print("  export MINI_HIDS_SMTP_USER=vanshiikagupta@gmail.com")
    print("  export MINI_HIDS_SMTP_PASS=vgzd gnvq okqr srzw\n")

    simulate_login_attempts(usernames=("attacker","unknown", "teacher"))  # teacher will be ignored by emailer
    simulate_file_events()
    simulate_net_process()

    # small pause to let emailer persist state
    time.sleep(1.0)
    show_recent_logs(150)
    print("\nSimulation finished. Check your email inbox + spam folder.")

if __name__ == "__main__":
    main()

