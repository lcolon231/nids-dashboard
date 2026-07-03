"""Map (port, protocol) -> NSL-KDD service names.

Only names that appear in KDDTrain+ are emitted — anything else would one-hot
encode to all zeros anyway (the backend transformer uses handle_unknown=
"ignore"). Unknown ports map to "private", matching how unregistered ports
were labeled in the original dataset. The mapping is an approximation of the
1998 /etc/services table the DARPA data was built from.
"""
from __future__ import annotations

TCP_SERVICES: dict[int, str] = {
    7: "echo",
    9: "discard",
    11: "systat",
    13: "daytime",
    15: "netstat",
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    42: "name",
    43: "whois",
    53: "domain",
    57: "mtp",
    70: "gopher",
    77: "rje",
    79: "finger",
    80: "http",
    84: "ctf",
    87: "link",
    95: "supdup",
    101: "hostnames",
    102: "iso_tsap",
    105: "csnet_ns",
    109: "pop_2",
    110: "pop_3",
    111: "sunrpc",
    113: "auth",
    117: "uucp_path",
    119: "nntp",
    139: "netbios_ssn",
    143: "imap4",
    150: "sql_net",
    179: "bgp",
    210: "Z39_50",
    389: "ldap",
    433: "nnsp",
    443: "http_443",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    530: "courier",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    2784: "http_2784",
    5190: "aol",
    6000: "X11",
    6667: "IRC",
    8001: "http_8001",
}

UDP_SERVICES: dict[int, str] = {
    53: "domain_u",
    69: "tftp_u",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
}

# ICMP "services" in NSL-KDD are message types.
ICMP_SERVICES: dict[int, str] = {
    0: "ecr_i",  # echo reply
    5: "red_i",  # redirect
    8: "eco_i",  # echo request
    11: "tim_i",  # time exceeded
    13: "tim_i",  # timestamp request
    14: "tim_i",  # timestamp reply
}


def service_name(proto: str, port: int, icmp_type: int = -1, icmp_code: int = -1) -> str:
    """NSL-KDD service label for a connection's responder port / ICMP type."""
    if proto == "icmp":
        if icmp_type == 3:  # destination unreachable
            return "urp_i" if icmp_code == 3 else "urh_i"
        return ICMP_SERVICES.get(icmp_type, "oth_i")
    if proto == "tcp":
        return TCP_SERVICES.get(port, "private")
    if proto == "udp":
        return UDP_SERVICES.get(port, "private")
    return "other"
