import sqlite3
import sys
import csv
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

def summary():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    print("DATABASE SUMMARY")

    for table in ["events", "traffic", "dhcp", "clients", "access_points"]:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        print(f"{table:15} {cur.fetchone()[0]}")

    conn.close()


def client(mac):
    rows = query("""
    SELECT time, src_ip, dst_ip, protocol, sport, dport
    FROM traffic
    WHERE client_mac=?
    ORDER BY time DESC
    LIMIT 50
    """, (mac,))

    print(f"CLIENT {mac}")
    for row in rows:
        print(row)


def timeline():
    rows = query("""
SELECT substr(time,1,13) AS hour, COUNT(*)
FROM events
WHERE time GLOB '____-__-__ __:*'
GROUP BY hour
ORDER BY hour
    """)

    print("TIMELINE")
    for hour, count in rows:
        print(f"{hour}: {count}")
        
def client_summary(mac, csv_file=None):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    print("CLIENT SUMMARY")
    print("MAC:", mac)

    cur.execute("""
    SELECT COUNT(*) FROM traffic
    WHERE client_mac=?
    """, (mac,))
    print("PACKETS:", cur.fetchone()[0])

    cur.execute("""
    SELECT MIN(time), MAX(time)
    FROM traffic
    WHERE client_mac=?
    """, (mac,))
    first, last = cur.fetchone()
    print("FIRST SEEN:", first)
    print("LAST SEEN:", last)

    print("\nTOP DESTINATIONS")
    cur.execute("""
    SELECT dst_ip, COUNT(*) cnt
    FROM traffic
    WHERE client_mac=?
    GROUP BY dst_ip
    ORDER BY cnt DESC
    LIMIT 10
    """, (mac,))

    for ip, cnt in cur.fetchall():
        print(f"{ip:20} {cnt}")

    print("\nTOP PORTS")
    cur.execute("""
    SELECT dport, COUNT(*) cnt
    FROM traffic
    WHERE client_mac=?
    GROUP BY dport
    ORDER BY cnt DESC
    LIMIT 10
    """, (mac,))

    for port, cnt in cur.fetchall():
        print(f"{str(port):10} {cnt}")
    if csv_file:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            writer.writerow(["CLIENT SUMMARY"])
            writer.writerow(["MAC", mac])
            writer.writerow(["PACKETS", packet_count])
            writer.writerow(["FIRST SEEN", first])
            writer.writerow(["LAST SEEN", last])

            writer.writerow([])
            writer.writerow(["DESTINATION", "COUNT"])
            for ip, cnt in destinations:
                writer.writerow([ip, cnt])

            writer.writerow([])
            writer.writerow(["PORT", "COUNT"])
            for port, cnt in ports:
                writer.writerow([port if port else "-", cnt])
                
    conn.close()
    
def help():
    print("""
Usage:

python raport.py clients
python raport.py src
python raport.py dst
python raport.py events
python raport.py dhcp
python raport.py summary
python raport.py client MAC
python raport.py timeline
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
    elif cmd == "summary":
        summary()
    elif cmd == "client":
        if len(sys.argv) < 3:
            help()
        else:
            client(sys.argv[2])
    elif cmd == "client-summary":
        if len(sys.argv) < 3:
            help()
        else:
            client_summary(
                sys.argv[2],
                sys.argv[4] if len(sys.argv) > 3 and sys.argv[3] == "--csv" else None
            )
    elif cmd == "timeline":
        timeline()