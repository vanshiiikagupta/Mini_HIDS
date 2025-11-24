# monitor/file_monitor.py
import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from storage.db import add_event
from utils.helpers import now_iso

# global callback to send alerts
_alert_callback = None

def set_alert_callback(cb):
    """Set the alert function from HIDS core"""
    global _alert_callback
    _alert_callback = cb

class _FileHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()

    def on_created(self, event):
        if event.is_directory:
            return
        ev = {
            "ts": now_iso(),
            "type": "file_created",
            "path": event.src_path,
            "user": os.getenv("USER") or ""
        }
        try:
            add_event(ev)
        except Exception:
            pass
        if _alert_callback:
            try:
                _alert_callback(ev)
            except Exception:
                pass

    def on_modified(self, event):
        if event.is_directory:
            return
        ev = {
            "ts": now_iso(),
            "type": "file_modified",
            "path": event.src_path,
            "user": os.getenv("USER") or ""
        }
        try:
            add_event(ev)
        except Exception:
            pass
        if _alert_callback:
            try:
                _alert_callback(ev)
            except Exception:
                pass

    def on_deleted(self, event):
        if event.is_directory:
            return
        ev = {
            "ts": now_iso(),
            "type": "file_deleted",
            "path": event.src_path,
            "user": os.getenv("USER") or ""
        }
        try:
            add_event(ev)
        except Exception:
            pass
        if _alert_callback:
            try:
                _alert_callback(ev)
            except Exception:
                pass

def start_file_monitor(paths):
    """
    Start monitoring the given list of paths.
    Returns a watchdog Observer object (you can stop it later with observer.stop())
    """
    if not isinstance(paths, list):
        paths = [paths]

    event_handler = _FileHandler()
    observer = Observer()
    for p in paths:
        if os.path.exists(p):
            observer.schedule(event_handler, p, recursive=True)
    observer.start()
    return observer

