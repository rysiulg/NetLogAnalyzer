import re
from datetime import datetime


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12
}


# łapie:
# 192.168.88.83 Jul 11 00:00:00
#
# oraz spacje/taby

syslog_time_re = re.compile(
    r'^\S+\s+'
    r'(?P<month>[A-Z][a-z]{2})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})'
)



def parse_time(line):

    m = syslog_time_re.search(line)


    if not m:
        return None


    year = datetime.now().year


    month = MONTHS.get(
        m.group("month")
    )


    if not month:
        return None


    day = int(
        m.group("day")
    )


    hour,minute,second = map(
        int,
        m.group("time").split(":")
    )


    return datetime(
        year,
        month,
        day,
        hour,
        minute,
        second
    ).isoformat(" ")