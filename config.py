# config.py
import os

# Paths to monitor
MONITOR_PATHS = [
    os.path.expanduser("~/Documents"),   # example folder to monitor
    os.path.expanduser("~/Desktop")
]

# Files to maintain baseline hashes 
BASELINE_FILE = "storage/baseline_hashes.json"

# Database path
DB_PATH = "storage/logs_encrypted.db"

# Email (SMTP) 
SMTP = {
    "host": "smtp.gmail.com",
    "port": 587,
    "username": "student.sender@gmail.com",
    # Gmail credentials
    "password": "16 character password",
    "from_addr": "student.sender@gmail.com",
    "to_addrs": ["teacher.receiver@gmail.com"]  # list of addresses to notify
}

# Monitoring thresholds
PROCESS_CPU_THRESHOLD = 50.0  
PROCESS_MEM_THRESHOLD = 60.0


# Encryption key location 
FERNET_KEY_NAME = "mini_hids_fernet_key"

