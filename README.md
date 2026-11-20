# Network Security and Firewall Monitoring System

A simple Python project that demonstrates basic network security concepts. It monitors
incoming and outgoing network traffic, applies firewall rules, classifies each packet as
**Allowed** or **Blocked**, detects suspicious activity, raises security alerts and keeps a
security log. (Common Assignment CSA07)

## Features
- Firewall rules based on source IP, destination IP, port number and protocol
- Add and delete rules from the menu (rules are saved in `rules.json`)
- Packets that match no rule are blocked by a default rule
- Traffic type identification (HTTP, HTTPS, DNS, SSH, Telnet, RDP ...)
- Suspicious activity detection: port scanning, repeated attempts from a blacklisted IP,
  access to restricted ports (Telnet, Remote Desktop) and traffic flooding (DoS)
- Security alerts, and automatic blocking of a flooding IP
- Security log saved in `security_log.txt`
- Network traffic dashboard (total, allowed, blocked, TCP, UDP, suspicious, alerts)

## Project Structure
| File | Purpose |
|------|---------|
| `main.py` | Menu and program start |
| `firewall.py` | Rule loading, saving and packet matching |
| `traffic.py` | Packet details, sample packets, random traffic |
| `detection.py` | Suspicious activity detection and alerts |
| `dashboard.py` | Log, alert and dashboard display |
| `rules.json` | Firewall rules |
| `docs/` | Assignment report (Word document) |

## How to Run
Requires Python 3.6 or above. No extra packages are needed.

```
python main.py
```

Choose option **5** to run the 10 sample packets, then options **7**, **8** and **9**
to see the log, alerts and dashboard.

## Rule Order
Rules are checked from top to bottom and the first match is used, so block rules are kept
above the allow rules.

## Sample Output
```
203.0.113.45 -> 192.168.1.10  port 80/TCP  (HTTP)  rule R5  => BLOCKED
198.51.100.23 -> 192.168.1.10  port 21/TCP  (FTP)  rule Default  => BLOCKED
    !! SECURITY ALERT: 198.51.100.23 - Port scan detected on 3 ports
```

## Future Improvements
Real packet capture, a graphical dashboard, and email alerts.
