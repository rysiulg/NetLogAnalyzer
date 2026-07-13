PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def protocol_name(proto):
    try:
        return PROTOCOLS.get(int(proto), str(proto))
    except:
        return "-"