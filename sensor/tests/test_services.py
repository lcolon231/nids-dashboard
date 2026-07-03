"""Port/protocol -> NSL-KDD service names."""
from nids_sensor.services import service_name


def test_common_tcp_ports():
    assert service_name("tcp", 80) == "http"
    assert service_name("tcp", 443) == "http_443"
    assert service_name("tcp", 21) == "ftp"
    assert service_name("tcp", 22) == "ssh"
    assert service_name("tcp", 23) == "telnet"
    assert service_name("tcp", 6667) == "IRC"


def test_udp_ports():
    assert service_name("udp", 53) == "domain_u"
    assert service_name("udp", 123) == "ntp_u"


def test_unknown_ports_map_to_private():
    assert service_name("tcp", 54321) == "private"
    assert service_name("udp", 54321) == "private"


def test_icmp_services():
    assert service_name("icmp", 0, icmp_type=8) == "eco_i"   # echo request
    assert service_name("icmp", 0, icmp_type=0) == "ecr_i"   # echo reply
    assert service_name("icmp", 0, icmp_type=3, icmp_code=3) == "urp_i"
    assert service_name("icmp", 0, icmp_type=3, icmp_code=1) == "urh_i"
    assert service_name("icmp", 0, icmp_type=42) == "oth_i"
