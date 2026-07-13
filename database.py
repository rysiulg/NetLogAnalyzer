import sqlite3
import os



DB="wifi_history.db"

print("DATABASE PATH:")
print(os.path.abspath(DB))

def get_connection():

    conn=sqlite3.connect(DB)

    return conn



def init_db():

    conn=get_connection()

    cur=conn.cursor()


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
    print("DATABASE INITIALIZED")


    conn.commit()
    conn.close()