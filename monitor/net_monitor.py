# monitor/net_monitor.py
import os, time
from utils.helpers import now_iso, read_json
from storage.db import add_event

try:
    import psutil
except Exception:
    psutil = None

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules.json")
def _load_rules():
    try:
        obj = read_json(RULES_PATH, default={})
        return {
            "suspicious_ports": obj.get("suspicious_ports", []),
            "suspicious_processes": obj.get("suspicious_processes", [])
        }
    except Exception:
        return {"suspicious_ports": [], "suspicious_processes": []}

RULES = _load_rules()

class NetMonitor:
    def __init__(self, polling=1.0):
        self.polling = float(polling)
        self._prev_conns = set()
        self._prev_listens = set()

    def _snapshot(self):
        conns = set()
        listens = set()
        if psutil is None:
            return conns, listens
        try:
            for c in psutil.net_connections(kind='inet'):
                try:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    key = (c.pid, c.status, laddr, raddr)
                    conns.add(key)
                    if c.status == psutil.CONN_LISTEN:
                        listens.add((c.pid, laddr))
                except Exception:
                    continue
        except Exception:
            pass
        return conns, listens

    def run_loop(self, stop_event, alert_callback):
        if psutil is None:
            add_event({"ts": now_iso(), "type":"net_monitor_missing_psutil"})
            return

        cur_conns, cur_listens = self._snapshot()
        self._prev_conns = cur_conns
        self._prev_listens = cur_listens

        while not stop_event.is_set():
            time.sleep(self.polling)
            cur_conns, cur_listens = self._snapshot()

            new_conns = cur_conns - self._prev_conns
            for pid, status, laddr, raddr in new_conns:
                ev = {"ts": now_iso(), "type": "net_connection", "pid": pid, "status": status, "local": laddr, "remote": raddr}
                try:
                    add_event(ev)
                except Exception:
                    pass

                try:
                    # if remote port in suspicious list -> escalate
                    if raddr:
                        try:
                            port = int(raddr.split(":")[-1])
                        except Exception:
                            port = None
                        if port and port in RULES.get("suspicious_ports", []):
                            sev = {"ts": now_iso(), "type": "suspicious_connection", "pid": pid, "local": laddr, "remote": raddr}
                            try:
                                add_event(sev)
                                alert_callback(sev)
                                continue
                            except Exception:
                                pass
                    alert_callback(ev)
                except Exception:
                    pass

            new_listens = cur_listens - self._prev_listens
            for pid, l in new_listens:
                ev = {"ts": now_iso(), "type":"listening_port", "pid": pid, "local": l}
                try:
                    add_event(ev)
                except Exception:
                    pass
                try:
                    try:
                        port = int(l.split(":")[-1])
                    except Exception:
                        port = None
                    if port and port in RULES.get("suspicious_ports", []):
                        sev = {"ts": now_iso(), "type":"suspicious_listen", "pid": pid, "local": l}
                        add_event(sev)
                        alert_callback(sev)
                    else:
                        alert_callback(ev)
                except Exception:
                    pass

            self._prev_conns = cur_conns
            self._prev_listens = cur_listens

        add_event({"ts": now_iso(), "type":"net_monitor_stopped"})


