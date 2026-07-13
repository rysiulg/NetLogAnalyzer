import re
from utils import normalize_mac


traffic_re = re.compile(
    r'AP MAC=(?P<ap>[0-9a-fA-F:]{17})\s+'
    r'MAC SRC=(?P<client>[0-9a-fA-F:]{17})\s+'
    r'IP SRC=(?P<src>\d+\.\d+\.\d+\.\d+)\s+'
    r'IP DST=(?P<dst>\d+\.\d+\.\d+\.\d+)'
    r'\s+IP proto=(?P<proto>\d+)'
    r'(?:\s+SPT=(?P<sport>\d+)\s+DPT=(?P<dport>\d+))?'
)


def parse_traffic(line):

    result=[]

    for m in traffic_re.finditer(line):

        result.append({

            "ap":
                normalize_mac(
                    m.group("ap")
                ),

            "client":
                normalize_mac(
                    m.group("client")
                ),

            "src":
                m.group("src"),

            "dst":
                m.group("dst"),

            "protocol":
                m.group("proto"),

            "sport":
                m.group("sport"),

            "dport":
                m.group("dport")

        })


    return result