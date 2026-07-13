import re
from utils import normalize_mac



dhcp_re=re.compile(
r'(?P<action>assigned|deassigned)\s+'
r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
r'(?:to|from)\s+'
r'(?P<mac>[0-9A-Fa-f:-]{17})'
)



def parse_dhcp(line):

    m=dhcp_re.search(line)

    if not m:
        return None


    return {

        "ip":
            m.group("ip"),

        "mac":
            normalize_mac(
                m.group("mac")
            ),

        "action":
            m.group("action")
    }