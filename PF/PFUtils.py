"""Miscellaneous network and PF-related utilities"""

import re
from socket import *


__all__ = ['getprotobynumber']


def getprotobynumber(number, file="/etc/protocols"):
    """Map a protocol number to a name.

    Return the protocol name or None if no match is found."""
    try:
        f = open(file, "r")
    except:
        return None     # Fail silently

    r = re.compile("(\S+)\s+(\d+)")

    for line in f:
        m = r.match(line.split("#")[0].strip())
        if m:
            proto, num = m.groups()
            if int(num) == number:
                return proto

    return None

