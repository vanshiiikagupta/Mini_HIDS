#!/bin/bash
set -e
cd "$(dirname "$0")/.."
source venv/bin/activate

echo "1) Simulate failed GUI login (attacker)"
python3 - <<'PY'
from storage.db import add_event
from utils.helpers import now_iso
from utils.emailer import send_email

ev = {"ts": now_iso(), "type":"gui_login_attempt", "user_entered":"attacker","result":"failed","source":"demo_script"}
add_event(ev)
# send email using per-username rate key (so it's one email per user)
rk = "auth_attacker_demo"
ok = send_email("[mini-HIDS] GUI login attempt by attacker", str(ev), rate_key=rk)
print("Added event; email send returned:", ok)
PY


echo "2) File create/modify/delete (Desktop)"
echo "hello" > ~/Desktop/mini_hids_demo_file.txt
sleep 1
echo "mod" >> ~/Desktop/mini_hids_demo_file.txt
sleep 1
rm ~/Desktop/mini_hids_demo_file.txt
echo "File events done"

echo "3) Start nc listener on 9999 (background)"
if command -v nc >/dev/null 2>&1; then
  nc -l 9999 >/dev/null 2>&1 &
  echo "nc started with PID $!"
else
  echo "nc not installed; skipping net listener"
fi

echo "Demo tests triggered. Check HIDS terminal for alerts and your email inbox for 1 email for 'attacker' (if cooldown allows)."

