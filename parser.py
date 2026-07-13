import re
import sqlite3
from datetime import datetime


LOGFILE = "syslog."
DB = "wifi_history.db"


conn = sqlite3.connect(DB)
cur = conn.cursor()


cur.executescript("""

CREATE TABLE IF NOT EXISTS dhcp (
    id INTEGER PRIMARY KEY,
    hash TEXT UNIQUE,
    hostname TEXT,
    time TEXT,
    mac TEXT,
    ip TEXT,
    action TEXT
);


CREATE TABLE IF NOT EXISTS wifi (
    id INTEGER PRIMARY KEY,
    hash TEXT UNIQUE,
    time TEXT,
    mac TEXT,
    ap TEXT,
    event TEXT
);


CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY,
    hash TEXT UNIQUE,
    time TEXT,
    ap TEXT,
    mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    sport TEXT,
    dport TEXT
);

CREATE TABLE IF NOT EXISTS ap_devices (
    mac TEXT PRIMARY KEY,
    name TEXT,
    location TEXT,
    vendor TEXT
);

CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    name TEXT,
    hostname TEXT,
    note TEXT,
    first_seen TEXT,
    last_seen TEXT
);
""")


# ----------------------------
# DHCP MikroTik
# ----------------------------

dhcp_re = re.compile(
    r'(?P<action>assigned|deassigned)\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?:from|to)\s+'
    r'(?P<mac>[0-9A-Fa-f:]{17})'
    r'(?P<host>[A-Za-z0-9\-_]+)?'
)


# ----------------------------
# AP traffic
# ----------------------------

traffic_re = re.compile(
    r'AP MAC=(?P<ap>[0-9A-Fa-f:]{17}).*?'
    r'MAC SRC=(?P<mac>[0-9A-Fa-f:]{17}).*?'
    r'IP SRC=(?P<src>\d+\.\d+\.\d+\.\d+)\s+'
    r'IP DST=(?P<dst>\d+\.\d+\.\d+\.\d+).*?'
    r'IP proto=(?P<proto>\d+)'
    r'(?:\s+SPT=(?P<sport>\d+)\s+DPT=(?P<dport>\d+))?'
)


# ----------------------------
# UniFi STA tracker
# ----------------------------

wifi_re = re.compile(
    r'"mac":"(?P<mac>[0-9A-Fa-f:]{17}).*?'
    r'"event_type":"(?P<event>[^"]+)'
)

ap_re = re.compile(
    r'^(?P<srcip>\S+)\s+'
    r'(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'.*?\s'
    r'(?P<mac>[0-9a-fA-F]{12}),'
    r'(?P<model>[^,\s]+)'
)

def now():
    return datetime.now().isoformat()

def add_client(mac, hostname=None):
    mac = normalize_mac(mac)

    cur.execute(
    """
    INSERT INTO clients
    (mac, hostname, first_seen, last_seen)
    VALUES(?,?,?,?)
    ON CONFLICT(mac)
    DO UPDATE SET
        last_seen=excluded.last_seen,
        hostname=COALESCE(excluded.hostname,hostname)
    """,
    (
        mac,
        hostname,
        timestamp,
        timestamp
    ))

def normalize_mac(mac):
    mac = mac.replace(":","").lower()
    return ":".join(mac[i:i+2] for i in range(0,12,2))

def add_ap(mac,name,model):

    mac = normalize_mac(mac)

    cur.execute(
    """
    INSERT INTO ap_devices
    (mac,name,vendor)
    VALUES(?,?,?)
    ON CONFLICT(mac)
    DO UPDATE SET
    name=excluded.name,
    vendor=excluded.vendor
    """,
    (
        mac,
        name,
        model
    ))

syslog_time_re = re.compile(
    r'^(?:\S+\s+)'              # IP źródłowe
    r'(?P<month>[A-Z][a-z]{2})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})'
)
months = {
    "Jan":"01",
    "Feb":"02",
    "Mar":"03",
    "Apr":"04",
    "May":"05",
    "Jun":"06",
    "Jul":"07",
    "Aug":"08",
    "Sep":"09",
    "Oct":"10",
    "Nov":"11",
    "Dec":"12"
}


def get_log_time(line):
    m = syslog_time_re.search(line)
    if not m:
        return None
    year = datetime.now().year
    return datetime.strptime(
        f"{year} {m.group('month')} {m.group('day')} {m.group('time')}",
        "%Y %b %d %H:%M:%S"
    ).isoformat(" ")

import glob
import hashlib


files = glob.glob("syslog*.*")

def make_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

for filename in files:
    print("Czytam:", filename)
    with open(filename, encoding="utf-8", errors="ignore") as f:
        for line in f:
            timestamp = get_log_time(line)
            # DHCP
            m = dhcp_re.search(line)
            if m:
                record = (
                    m.group("mac").lower()+
                    m.group("ip")+
                    m.group("action")
                )

                record_hash = make_hash(record)
                add_client(m.group("mac"))
                cur.execute(
                    """
                    INSERT OR IGNORE INTO dhcp
                    (hash,hostname,time,mac,ip,action)
                    VALUES(?,?,?,?,?,?)
                    """,
                    (
                        record_hash,
                        m.group("host"),
                        timestamp,
                        m.group("mac").lower(),
                        m.group("ip"),
                        m.group("action")
                    )
                )
            # AP traffic
            m = traffic_re.search(line)
            if m:
                record = (
                    m.group("ap")+
                    m.group("mac").lower()+
                    m.group("src")+
                    m.group("dst")+
                    m.group("proto")+
                    str(m.group("sport"))+
                    str(m.group("dport"))
                )

                record_hash = make_hash(record)
                add_client(m.group("mac"))
                cur.execute(
                    """
                    INSERT OR IGNORE INTO traffic
                    (hash,time,ap,mac,src_ip,dst_ip,protocol,sport,dport)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record_hash,
                        timestamp,
                        m.group("ap"),
                        m.group("mac").lower(),
                        m.group("src"),
                        m.group("dst"),
                        m.group("proto"),
                        m.group("sport"),
                        m.group("dport")
                    )
                )
            # STA tracker
            m = wifi_re.search(line)
            if m:
                record = (
                    m.group("mac").lower()+
                    m.group("event")
                )

                record_hash = make_hash(record)
                add_client(m.group("mac"))
                cur.execute(
                    """
                    INSERT OR IGNORE INTO wifi
                    VALUES(NULL,?,?,?,?,?)
                    """,
                    (
                        record_hash,
                        timestamp,
                        m.group("mac"),
                        "unknown",
                        m.group("event")
                    )
                )

            m = ap_re.search(line)
            if m:
                add_ap(
                    m.group("mac"),
                    m.group("hostname"),
                    m.group("model")
                )

conn.commit()
conn.close()

print("OK - log zaimportowany")