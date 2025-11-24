# monitor/rules.py
import json, os
from utils.helpers import read_json

RULES_PATH = "rules.json"

def load_rules():
    r = read_json(RULES_PATH, default={})
    return r

def check_process_name(proc_name):
    rules = load_rules()
    s = rules.get("suspicious_processes", [])
    return any(x.lower() in proc_name.lower() for x in s)

def check_port(port):
    rules = load_rules()
    return port in rules.get("suspicious_ports", [])

