import sqlite3
import sys
from database import DB

def query(sql, params=()):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def top_clients(limit=20):
    rows = query("""
    SELECT client_mac, COUNT(*) AS cnt
    FROM traffic
    GROUP BY client_mac
    ORDER BY cnt DESC
    LIMIT ?
    """, (limit,))

    print("TOP CLIENTS")
    for mac, cnt in rows:
        print(f"{mac:20} {cnt}")

def top_src_ip(limit=20):
    rows = query("""
    SELECT src_ip, COUNT(*) AS cnt
    FROM traffic
    GROUP BY src_ip
    ORDER BY cnt DESC
    LIMIT ?
    """, (limit,))

    print("TOP SOURCE IP")
    for ip, cnt in rows:
        print(f"{ip:20} {cnt}")

def top_dst_ip(limit=20):
    rows = query("""
    SELECT dst_ip, COUNT(*) AS cnt
    FROM traffic
    GROUP BY dst_ip
    ORDER BY cnt DESC
    LIMIT ?
    """, (limit,))

    print("TOP DESTINATION IP")
    for ip, cnt in rows:
        print(f"{ip:20} {cnt}")

def events(limit=20):
    rows = query("""
    SELECT event, COUNT(*) AS cnt
    FROM events
    GROUP BY event
    ORDER BY cnt DESC
    LIMIT ?
    """, (limit,))

    print("EVENTS")
    for event, cnt in rows:
        print(f"{event:20} {cnt}")

def dhcp(limit=20):
    rows = query("""
    SELECT ip, mac, COUNT(*) AS cnt
    FROM dhcp
    GROUP BY ip, mac
    ORDER BY cnt DESC
    LIMIT ?
    """, (limit,))

    print("DHCP")
    for ip, mac, cnt in rows:
        print(f"{ip:16} {mac:20} {cnt}")

def help():
    print("""
Usage:

python raport.py clients
python raport.py src
python raport.py dst
python raport.py events
python raport.py dhcp
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help()
        sys.exit()

    cmd = sys.argv[1]

    if cmd == "clients":
        top_clients()
    elif cmd == "src":
        top_src_ip()
    elif cmd == "dst":
        top_dst_ip()
    elif cmd == "events":
        events()
    elif cmd == "dhcp":
        dhcp()
    else:
        help()