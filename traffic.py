"""Packet details, traffic types, sample data and random traffic."""
import random

SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
}


def traffic_type(port):
    return SERVICES.get(port, "Other")


def make_packet(src, dst, port, protocol):
    return {"src": src, "dst": dst, "port": int(port), "protocol": protocol.upper()}


# Same 10 packets as the sample log in the assignment document
SAMPLE_PACKETS = [
    make_packet("192.168.1.15",  "8.8.8.8",      53,   "UDP"),
    make_packet("103.25.14.7",   "192.168.1.10", 443,  "TCP"),
    make_packet("203.0.113.45",  "192.168.1.10", 80,   "TCP"),
    make_packet("198.51.100.23", "192.168.1.10", 23,   "TCP"),
    make_packet("198.51.100.23", "192.168.1.10", 22,   "TCP"),
    make_packet("45.33.12.9",    "192.168.1.20", 3389, "TCP"),
    make_packet("117.200.5.88",  "192.168.1.10", 80,   "TCP"),
    make_packet("192.168.1.22",  "1.1.1.1",      53,   "UDP"),
    make_packet("198.51.100.23", "192.168.1.10", 21,   "TCP"),
    make_packet("203.0.113.45",  "192.168.1.10", 80,   "TCP"),
]

_EXTERNAL = ["103.25.14.7", "117.200.5.88", "45.33.12.9", "198.51.100.23",
             "203.0.113.45", "91.134.22.5", "185.220.101.4"]
_INTERNAL = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.22"]
_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]


def random_packet():
    """Make a random packet: about 60% normal traffic, 40% random (often attacks)."""
    r = random.random()
    if r < 0.25:
        return make_packet(random.choice(_EXTERNAL), "192.168.1.10", 80, "TCP")
    if r < 0.40:
        return make_packet(random.choice(_EXTERNAL), "192.168.1.10", 443, "TCP")
    if r < 0.60:
        return make_packet(random.choice(_INTERNAL), random.choice(["8.8.8.8", "1.1.1.1"]), 53, "UDP")
    port = random.choice(_PORTS)
    proto = "UDP" if port == 53 else "TCP"
    if random.random() < 0.75:      # incoming
        return make_packet(random.choice(_EXTERNAL), random.choice(_INTERNAL), port, proto)
    return make_packet(random.choice(_INTERNAL), random.choice(_EXTERNAL), port, proto)
