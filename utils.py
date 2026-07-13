import hashlib


def normalize_mac(mac):

    mac = (
        mac
        .replace(":","")
        .replace("-","")
        .lower()
    )

    return ":".join(
        mac[i:i+2]
        for i in range(0,12,2)
    )



def make_hash(text):

    return hashlib.sha256(
        text.encode()
    ).hexdigest()
    