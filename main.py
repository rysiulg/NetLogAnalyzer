import glob
import sqlite3

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



files=glob.glob(
    "syslog/*"
)



current_ap=None



def save_ap(data,time):

    if not data:
        return


    cur.execute(
    """
    INSERT INTO access_points
    (mac,name,model,ip,first_seen,last_seen)
    VALUES(?,?,?,?,?,?)

    ON CONFLICT(mac)
    DO UPDATE SET

    name=excluded.name,
    model=excluded.model,
    ip=excluded.ip,
    last_seen=excluded.last_seen

    """,
    (
        data["id"],
        data["name"],
        data["model"],
        data["ip"],
        time,
        time
    ))




def save_client(mac,time):

    cur.execute(
    """
    INSERT INTO clients
    (mac,first_seen,last_seen)

    VALUES(?,?,?)

    ON CONFLICT(mac)

    DO UPDATE SET
    last_seen=excluded.last_seen

    """,
    (
        mac,
        time,
        time
    ))





def save_client_ap(
        client,
        ap,
        time,
        event,
        vap=None
):


    cur.execute(
    """
    INSERT INTO client_ap
    (
    time,
    client_mac,
    ap_mac,
    event,
    vap
    )

    VALUES(?,?,?,?,?)

    """,

    (
        time,
        client,
        ap,
        event,
        vap
    )
    )




def save_dhcp(data,time):


    cur.execute(
    """

    INSERT INTO dhcp
    (
    time,
    mac,
    ip,
    action
    )

    VALUES(?,?,?,?)

    """,

    (
        time,
        data["mac"],
        data["ip"],
        data["action"]
    )
    )




def save_traffic(x,time):


    cur.execute(
    """

    INSERT INTO traffic

    (
    time,
    ap_mac,
    client_mac,
    src_ip,
    dst_ip,
    protocol,
    sport,
    dport
    )

    VALUES(?,?,?,?,?,?,?,?)

    """,

    (

        time,

        x["ap"],

        x["client"],

        x["src"],

        x["dst"],

        x["protocol"],

        x["sport"],

        x["dport"]

    ))



for filename in files:


    print(
        "Czytam",
        filename
    )


    with open(
        filename,
        encoding="utf-8",
        errors="ignore"
    ) as f:


        for line in f:


            timestamp=parse_time(line)


            if not timestamp:
                continue



            # AP informacje

            ap=parse_ap_info(line)


            if ap:

                save_ap(
                    ap,
                    timestamp
                )



            ap_mac=parse_ap_mac(line)


            if ap_mac:

                current_ap=ap_mac



            # STA tracker

            sta=parse_sta(line)


            if sta:


                save_client(
                    sta["mac"],
                    timestamp
                )


                if current_ap:


                    save_client_ap(

                        sta["mac"],

                        current_ap,

                        timestamp,

                        sta["event"],

                        sta["vap"]

                    )



            # DHCP

            dhcp=parse_dhcp(line)


            if dhcp:


                save_client(
                    dhcp["mac"],
                    timestamp
                )


                save_dhcp(
                    dhcp,
                    timestamp
                )




            # Traffic

            traffic=parse_traffic(line)


            for t in traffic:


                save_client(
                    t["client"],
                    timestamp
                )


                save_client_ap(

                    t["client"],

                    t["ap"],

                    timestamp,

                    "traffic"

                )


                save_traffic(
                    t,
                    timestamp
                )





conn.commit()

conn.close()


print(
"IMPORT OK"
)