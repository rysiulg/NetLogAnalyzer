import sqlite3
import sys
import csv
from datetime import datetime
from database import DB
from protocol import protocol_name

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
SELECT substr(time,1,13), COUNT(*)
FROM traffic
WHERE time != ''
GROUP BY substr(time,1,13)
ORDER BY substr(time,1,13)
    """)

    print("TIMELINE")
    for hour, count in rows:
        print(f"{hour}: {count}")


def _mac_key(mac):
    return (mac or "").replace(":", "").replace("-", "").lower()


def _access_points(conn):
    """Return AP details indexed by MAC, accepting colonless legacy MAC values."""
    rows = conn.execute("SELECT mac, name, model, ip FROM access_points").fetchall()
    return {
        _mac_key(mac): {"name": name, "model": model, "ip": ip}
        for mac, name, model, ip in rows
    }


def _format_duration(seconds):
    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _ap_label(metadata):
    """Prefer a friendly AP name and fall back to the source IP when absent."""
    return metadata.get("name") or metadata.get("ip") or "-"


def _traffic_sessions(rows, gap_minutes):
    """Split ordered traffic observations into AP-presence sessions."""
    gap_seconds = gap_minutes * 60
    sessions = []
    current = None

    for timestamp, ap_mac in rows:
        try:
            seen = datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            continue

        if (
            current is None
            or ap_mac != current["ap_mac"]
            or (seen - current["last_seen"]).total_seconds() > gap_seconds
        ):
            if current:
                sessions.append(current)
            current = {
                "ap_mac": ap_mac,
                "first_seen": seen,
                "last_seen": seen,
                "packets": 1,
            }
        else:
            current["last_seen"] = seen
            current["packets"] += 1

    if current:
        sessions.append(current)
    return sessions


def client_history(mac, gap_minutes=15, csv_file=None):
    """Show inferred AP-presence sessions from the client's traffic records.

    The log sources currently do not expose reliable disconnect events, therefore
    the start and end columns mean first and last observed traffic on an AP.
    """
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT time, ap_mac
        FROM traffic
        WHERE client_mac=? AND time GLOB '????-??-?? ??:??:??' AND ap_mac != ''
        ORDER BY time
    """, (mac,)).fetchall()

    sessions = _traffic_sessions(rows, gap_minutes)
    ap_by_mac = _access_points(conn)

    print("CLIENT AP HISTORY")
    print("MAC:", mac)
    print(f"Sessions inferred from traffic; a gap over {gap_minutes} minutes starts a new session.")
    print("START                END                  DURATION   AP MAC              AP NAME / IP            PACKETS")

    csv_rows = []
    for session in sessions:
        metadata = ap_by_mac.get(_mac_key(session["ap_mac"]), {})
        name = _ap_label(metadata)
        duration = _format_duration((session["last_seen"] - session["first_seen"]).total_seconds())
        start = session["first_seen"].isoformat(" ")
        end = session["last_seen"].isoformat(" ")
        print(
            f"{start:20} {end:20} {duration:10} "
            f"{session['ap_mac']:18} {name[:23]:23} {session['packets']}"
        )
        csv_rows.append((
            start,
            end,
            duration,
            session["ap_mac"],
            name,
            metadata.get("model") or "",
            metadata.get("ip") or "",
            session["packets"],
        ))

    if not sessions:
        print("No traffic observations found for this client.")

    if csv_file:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["CLIENT AP HISTORY"])
            writer.writerow(["MAC", mac])
            writer.writerow(["GAP MINUTES", gap_minutes])
            writer.writerow([])
            writer.writerow(["FIRST SEEN", "LAST SEEN", "DURATION", "AP MAC", "AP NAME", "AP MODEL", "AP IP", "PACKETS"])
            writer.writerows(csv_rows)

    conn.close()


def client_aps(mac):
    """Summarize every AP on which traffic from a client was observed."""
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT ap_mac, MIN(time), MAX(time), COUNT(*)
        FROM traffic
        WHERE client_mac=? AND ap_mac != ''
        GROUP BY ap_mac
        ORDER BY COUNT(*) DESC
    """, (mac,)).fetchall()
    ap_by_mac = _access_points(conn)

    print("CLIENT ACCESS POINTS")
    print("AP MAC              AP NAME / IP            FIRST SEEN           LAST SEEN            PACKETS")
    for ap_mac, first_seen, last_seen, packets in rows:
        name = _ap_label(ap_by_mac.get(_mac_key(ap_mac), {}))
        print(f"{ap_mac:18} {name[:23]:23} {str(first_seen):20} {str(last_seen):20} {packets}")
    conn.close()


def client_sta_events(mac):
    """List association-tracker events captured for a client during import."""
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT time, ap_mac, event, vap
        FROM client_ap
        WHERE client_mac=? AND event != 'traffic'
        ORDER BY time
    """, (mac,)).fetchall()
    ap_by_mac = _access_points(conn)

    print("CLIENT STA EVENTS")
    print("TIME                 EVENT                 VAP      AP MAC              AP NAME / IP")
    for event_time, ap_mac, event, vap in rows:
        name = _ap_label(ap_by_mac.get(_mac_key(ap_mac), {}))
        print(f"{str(event_time):20} {str(event):21} {str(vap or '-'):8} {str(ap_mac):18} {name}")
    if not rows:
        print("No STA events captured. Re-import the logs after updating the importer.")
    conn.close()
        
def client_summary(mac, csv_file=None):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    print("CLIENT SUMMARY")
    print("MAC:", mac)

    cur.execute("""
    SELECT COUNT(*) FROM traffic
    WHERE client_mac=?
    """, (mac,))
    count = cur.fetchone()[0]
    print("PACKETS:", count)

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

    destinations = cur.fetchall()
    for ip, cnt in destinations:
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
    
    ports = cur.fetchall()
    for port, cnt in ports:
        print(f"{str(port):10} {cnt}")
    
    print("\nPROTOCOLS")
    cur.execute("""
SELECT protocol, COUNT(*)
FROM traffic
WHERE client_mac=?
GROUP BY protocol
ORDER BY COUNT(*) DESC
""", (mac,))

    for proto, cnt in cur.fetchall():
        print(f"{protocol_name(proto):10} {cnt}")
    
    if csv_file:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            writer.writerow(["CLIENT SUMMARY"])
            writer.writerow(["MAC", mac])
            writer.writerow(["PACKETS", count])
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
python raport.py client-summary MAC [--csv FILE]
python raport.py client-history MAC [--gap-minutes N] [--csv FILE]
python raport.py client-aps MAC
python raport.py client-sta-events MAC
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
    elif cmd == "client-history":
        if len(sys.argv) < 3:
            help()
        else:
            args = sys.argv[3:]
            gap_minutes = 15
            csv_file = None
            if "--gap-minutes" in args:
                position = args.index("--gap-minutes")
                try:
                    gap_minutes = int(args[position + 1])
                except (IndexError, ValueError):
                    print("--gap-minutes requires a whole number")
                    sys.exit(2)
            if "--csv" in args:
                position = args.index("--csv")
                try:
                    csv_file = args[position + 1]
                except IndexError:
                    print("--csv requires a file path")
                    sys.exit(2)
            client_history(sys.argv[2], gap_minutes, csv_file)
    elif cmd == "client-aps":
        if len(sys.argv) < 3:
            help()
        else:
            client_aps(sys.argv[2])
    elif cmd == "client-sta-events":
        if len(sys.argv) < 3:
            help()
        else:
            client_sta_events(sys.argv[2])
    elif cmd == "timeline":
        timeline()
