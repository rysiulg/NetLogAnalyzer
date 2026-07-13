import re
import json
from utils import normalize_mac


sta_re=re.compile(
    r'stahtd_dump_event\(\): (?P<json>\{.*\})'
)



def parse_sta(line):

    m=sta_re.search(line)

    if not m:
        return None


    try:
        data=json.loads(
            m.group("json")
        )

    except:
        return None


    if "mac" not in data:
        return None


    return {

        "mac":
            normalize_mac(
                data["mac"]
            ),

        "vap":
            data.get(
                "vap"
            ),

        "event":
            data.get(
                "event_type"
            )
    }