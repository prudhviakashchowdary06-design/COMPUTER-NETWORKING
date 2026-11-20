"""Suspicious activity detection and security alerts."""

RESTRICTED_PORTS = {23, 3389}   # Telnet, Remote Desktop
SCAN_LIMIT = 3                  # different blocked ports from one IP => port scan
REPEAT_LIMIT = 2                # blocked tries from a blacklisted IP
FLOOD_LIMIT = 15                # blocked packets from one IP in one session => possible DoS

# higher number = more serious alert
LEVELS = {"restricted": 1, "repeat": 2, "scan": 3, "flood": 4}


class Detector:
    def __init__(self):
        self.packets = {}       # source ip -> packet count
        self.blocked_ports = {} # source ip -> set of blocked ports
        self.blacklist_hits = {}  # source ip -> blocked count by a rule on that IP
        self.alerts = {}        # source ip -> {"level", "message", "action"}

    def reason(self, entry):
        """Why a blocked packet is suspicious (returns '-' for allowed ones)."""
        if entry["status"] == "Allowed":
            return "-"
        if entry["port"] in RESTRICTED_PORTS:
            return "Access to restricted port " + str(entry["port"])
        if entry["rule"] == "Default":
            return "Probe on unlisted port"
        return "Blacklisted source"

    def analyse(self, entry):
        """Update counters and return a NEW/UPGRADED alert dict, or None."""
        ip = entry["src"]
        if entry["status"] == "Allowed":
            return None
        self.packets[ip] = self.packets.get(ip, 0) + 1   # only blocked packets count towards flooding

        ports = self.blocked_ports.setdefault(ip, set())
        ports.add(entry["port"])
        if entry["rule"] not in ("Default",) and entry["port"] not in RESTRICTED_PORTS:
            self.blacklist_hits[ip] = self.blacklist_hits.get(ip, 0) + 1

        level, msg = None, None
        if self.packets[ip] > FLOOD_LIMIT:
            level, msg = "flood", "Possible DoS flood (%d packets)" % self.packets[ip]
        elif len(ports) >= SCAN_LIMIT:
            level, msg = "scan", "Port scan detected on %d ports" % len(ports)
        elif self.blacklist_hits.get(ip, 0) >= REPEAT_LIMIT:
            level, msg = "repeat", "Repeated attempts from blacklisted IP"
        elif entry["port"] in RESTRICTED_PORTS:
            name = "remote desktop" if entry["port"] == 3389 else "telnet"
            level, msg = "restricted", "Unauthorized %s attempt" % name

        if level is None:
            return None
        old = self.alerts.get(ip)
        if old and LEVELS[old["level"]] >= LEVELS[level] and old["message"] == msg:
            return None
        if old and LEVELS[old["level"]] > LEVELS[level]:
            return None
        alert = {"ip": ip, "level": level, "message": msg, "action": "Packets blocked"}
        self.alerts[ip] = alert
        return alert
