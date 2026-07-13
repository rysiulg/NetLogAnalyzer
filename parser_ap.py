import re
from utils import normalize_mac

ap_info_re = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+'
    r'(?P<name>\S+).*?'
    r'(?P<id>[0-9a-fA-F]{12}),'
    r'(?P<model>[^,\s]+)'
)

ap_mac_re = re.compile(
    r'AP MAC=(?P<mac>[0-9a-fA-F:]{17})'
)

def parse_ap_info(line):
    m = ap_info_re.search(line)
    if not m:
        return None


    return {
        "ip":m.group("ip"),
        "name":m.group("name"),
        "id":normalize_mac(m.group("id")),
        "model":m.group("model")
    }



def parse_ap_mac(line):

    m=ap_mac_re.search(line)

    if not m:
        return None


    return normalize_mac(
        m.group("mac")
    )
