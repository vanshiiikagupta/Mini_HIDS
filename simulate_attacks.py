import os
import time
from utils.emailer import send_email

TEST_FILE = os.path.expanduser("~/Desktop/hids_test_demo.txt")

def alert(event_type, file_path):
    subject = f"[HIDS-DEMO] File {event_type}: {os.path.basename(file_path)}"
    body = f"Event: {event_type}\nPath: {file_path}"
    # rate_key prevents email spam
    send_email(subject, body, rate_key=f"demo_{event_type}")

print("\n=== HIDS DEMO — FILE OPERATIONS ===\n")

# 1️⃣ CREATE
print("[1] Creating file...")
with open(TEST_FILE, "w") as f:
    f.write("This is a demo file.\n")
alert("CREATED", TEST_FILE)
time.sleep(2)

# 2️⃣ MODIFY
print("[2] Modifying file...")
with open(TEST_FILE, "a") as f:
    f.write("File modified.\n")
alert("MODIFIED", TEST_FILE)
time.sleep(2)

# 3️⃣ DELETE
print("[3] Deleting file...")
os.remove(TEST_FILE)
alert("DELETED", TEST_FILE)

print("\n=== DEMO COMPLETE — CHECK YOUR EMAIL ===\n")

