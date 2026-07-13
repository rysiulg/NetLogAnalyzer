import sqlite3
import os



DB="wifi_history.db"
def get_connection():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    return conn



def init_db():

    conn=get_connection()

    cur=conn.cursor()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    cur.executescript("""

    CREATE TABLE IF NOT EXISTS access_points
    (
        id INTEGER PRIMARY KEY,
        mac TEXT UNIQUE,
        name TEXT,
        model TEXT,
        ip TEXT,
        first_seen TEXT,
        last_seen TEXT
    );


    CREATE TABLE IF NOT EXISTS clients
    (
        id INTEGER PRIMARY KEY,
        mac TEXT UNIQUE,
        name TEXT,
        hostname TEXT,
        first_seen TEXT,
        last_seen TEXT
    );


    CREATE TABLE IF NOT EXISTS client_ap
    (
        id INTEGER PRIMARY KEY,
        time TEXT,
        client_mac TEXT,
        ap_mac TEXT,
        event TEXT,
        vap TEXT
    );


    CREATE TABLE IF NOT EXISTS dhcp
    (
        id INTEGER PRIMARY KEY,
        time TEXT,
        mac TEXT,
        ip TEXT,
        hostname TEXT,
        action TEXT
    );


    CREATE TABLE IF NOT EXISTS traffic
    (
        id INTEGER PRIMARY KEY,
        time TEXT,
        ap_mac TEXT,
        client_mac TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        sport TEXT,
        dport TEXT
    );


    CREATE TABLE IF NOT EXISTS events
    (
        id INTEGER PRIMARY KEY,
        time TEXT,
        source TEXT,
        mac TEXT,
        event TEXT,
        raw TEXT
    );


    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic(time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_client ON traffic(client_mac)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_client_time ON traffic(client_mac, time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_dst ON traffic(dst_ip)")
    
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event)")
    
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_ip ON dhcp(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp(mac)")
    print("DATABASE INITIALIZED")


    conn.commit()
    conn.close()
