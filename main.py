import glob
import re
import sqlite3
from datetime import datetime

from database import DB, init_db
from parser_time import parse_time
from parser_ap import parse_ap_info, parse_ap_mac
from parser_sta import parse_sta
from parser_dhcp import parse_dhcp
from parser_traffic import parse_traffic
from utils import normalize_mac

init_db()
conn = sqlite3.connect(DB)
cur = conn.cursor()
counter = 0

MAC_RE = re.compile(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b')
CSV_TIME_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$')

def save_ap(data, ts):
    if not data:
        return
    cur.execute("""
    INSERT INTO access_points (mac,name,model,ip,first_seen,last_seen)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(mac) DO UPDATE SET
    name=excluded.name,
    model=excluded.model,
    ip=excluded.ip,
    last_seen=excluded.last_seen
    """, (data["id"], data["name"], data["model"], data["ip"], ts, ts))

def save_client(mac, ts, hostname=None, name=None):
    mac = normalize_mac(mac)
    cur.execute("""
    INSERT INTO clients (mac,name,hostname,first_seen,last_seen)
    VALUES(?,?,?,?,?)
    ON CONFLICT(mac) DO UPDATE SET
    name=COALESCE(excluded.name,clients.name),
    hostname=COALESCE(excluded.hostname,clients.hostname),
    last_seen=excluded.last_seen
    """, (mac, name, hostname, ts, ts))

def save_client_ap(client, ap, ts, event, vap=None):
    cur.execute("""
    INSERT INTO client_ap (time,client_mac,ap_mac,event,vap)
    VALUES(?,?,?,?,?)
    """, (ts, client, ap, event, vap))

def save_dhcp(data, ts):
    cur.execute("""
    INSERT INTO dhcp (time,mac,ip,hostname,action)
    VALUES(?,?,?,?,?)
    """, (ts, data["mac"], data["ip"], data.get("host"), data["action"]))

def save_traffic(x, ts):
    cur.execute("""
    INSERT INTO traffic (time,ap_mac,client_mac,src_ip,dst_ip,protocol,sport,dport)
    VALUES(?,?,?,?,?,?,?,?)
    """, (ts, x["ap"], x["client"], x["src"], x["dst"], x["protocol"], x["sport"], x["dport"]))

def save_event(ts, source, mac, event, raw=None):
    cur.execute("""
    INSERT INTO events (time,source,mac,event,raw)
    VALUES(?,?,?,?,?)
    """, (ts, source, mac, event, None))

def parse_csv_time(text):
    if not text:
        return None
    text = " ".join(text.replace("\xa0", " ").split())
    try:
        return datetime.strptime(f"{datetime.now().year} {text}", "%Y %b %d %H:%M:%S").isoformat(" ")
    except ValueError:
        return text

def parse_csv_line(line):
    parts = line.rstrip("\n").split("\t", 6)
    if len(parts) < 7:
        return None
    return {
        "source_ip": parts[0].strip() or None,
        "time": parse_csv_time(parts[1].strip()) if parts[1].strip() else None,
        "hostname": parts[2].strip() or None,
        "facility": parts[3].strip() or None,
        "severity": parts[4].strip() or None,
        "device": parts[5].strip() or None,
        "message": parts[6].strip() or ""
    }

def first_mac(text):
    m = MAC_RE.search(text or "")
    return normalize_mac(m.group(0)) if m else None

files = sorted(set(glob.glob("syslog/*") + glob.glob("syslog*.*")))

for filename in files:
    print("Czytam", filename)
    with open(filename, encoding="utf-8", errors="ignore") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue

            if "\t" in raw and filename.lower().endswith(".csv"):
                rec = parse_csv_line(raw)
                if not rec:
                    continue
                ts = rec["time"]
                msg = rec["message"]
                source = rec["hostname"] or rec["source_ip"]
                mac = first_mac(rec["device"] or "") or first_mac(msg)

                traffic = parse_traffic(msg)
                if traffic:
                    for t in traffic:
                        save_client(t["client"], ts, source)
                        save_traffic(t, ts)
                        save_client_ap(t["client"], t["ap"], ts, "traffic")
                        save_event(ts, source, t["client"], "traffic", raw)
                    continue

                dhcp = parse_dhcp(msg)
                if dhcp:
                    save_client(dhcp["mac"], ts, source)
                    save_dhcp(dhcp, ts)
                    save_event(ts, source, dhcp["mac"], "dhcp", raw)
                    continue

                sta = parse_sta(msg)
                if sta:
                    save_client(sta["mac"], ts, source)
                    save_event(ts, source, sta["mac"], "sta", raw)
                    continue

                if rec["device"] and rec["device"].strip():
                    ap_mac = first_mac(rec["device"])
                    if ap_mac:
                        save_ap({"id": ap_mac, "name": source, "model": rec["device"], "ip": rec["source_ip"]}, ts)
                save_event(ts, source, mac, rec["facility"] or "syslog", raw)
                counter += 1
                if counter % 5000 == 0:
                    conn.commit()
                    print(counter)
                continue

            timestamp = parse_time(raw)
            if not timestamp:
                continue

            ap = parse_ap_info(raw)
            if ap:
                save_ap(ap, timestamp)

            ap_mac = parse_ap_mac(raw)
            if ap_mac:
                current_ap = ap_mac
            else:
                current_ap = None

            sta = parse_sta(raw)
            if sta:
                save_client(sta["mac"], timestamp)
                if current_ap:
                    save_client_ap(sta["mac"], current_ap, timestamp, sta["event"], sta["vap"])
                save_event(timestamp, "syslog", sta["mac"], "sta", raw)
                counter += 1
                if counter % 5000 == 0:
                    conn.commit()
                    print(counter)

            dhcp = parse_dhcp(raw)
            if dhcp:
                save_client(dhcp["mac"], timestamp)
                save_dhcp(dhcp, timestamp)
                save_event(timestamp, "syslog", dhcp["mac"], "dhcp", raw)
                counter += 1
                if counter % 5000 == 0:
                    conn.commit()
                    print(counter)

            traffic = parse_traffic(raw)
            for t in traffic:
                save_client(t["client"], timestamp)
                save_traffic(t, timestamp)
                save_event(timestamp, "syslog", t["client"], "traffic")
                counter += 1
                if counter % 5000 == 0:
                    conn.commit()
                    print(counter)

conn.commit()
conn.close()
print("IMPORT OK")