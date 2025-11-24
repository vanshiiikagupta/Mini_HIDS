# storage/db.py
import sqlite3
import json
from utils.crypto_utils import get_fernet
from utils.helpers import ensure_dir
import os

DB_PATH = "storage/logs_encrypted.db"

def init_db():
    ensure_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        enc_event BLOB
    )
    ''')
    conn.commit()
    conn.close()

def add_event(event_dict):
    f = get_fernet()
    enc = f.encrypt(json.dumps(event_dict).encode())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO events (ts, enc_event) VALUES (?, ?)", (event_dict.get("ts"), enc))
    conn.commit()
    conn.close()

def get_events(limit=100):
    f = get_fernet()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, ts, enc_event FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    out = []
    for r in rows:
        try:
            dec = f.decrypt(r[2])
            out.append((r[0], r[1], json.loads(dec)))
        except Exception:
            out.append((r[0], r[1], {"error":"decrypt_failed"}))
    return out

