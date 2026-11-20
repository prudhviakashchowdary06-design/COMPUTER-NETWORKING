"""Network Security and Firewall Monitoring System - main program."""
import os
import random
from datetime import datetime

import firewall
import traffic
import detection
import dashboard

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_log.txt")

rules = firewall.load_rules()
detector = detection.Detector()
log = []


def process_packet(packet, show=True):
    """Check one packet against the firewall, record it, and raise alerts."""
    rule_id, action = firewall.check_packet(packet, rules)
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": packet["src"], "dst": packet["dst"],
        "port": packet["port"], "protocol": packet["protocol"],
        "rule": rule_id,
        "type": traffic.traffic_type(packet["port"]),
        "status": "Allowed" if action == "Allow" else "Blocked",
    }
    entry["suspicious"] = detector.reason(entry)
    log.append(entry)

    with open(LOG_FILE, "a") as f:
        f.write("{time} | {src} -> {dst} | port {port}/{protocol} | {type} | rule {rule} | "
                "{status} | {suspicious}\n".format(**entry))

    if show:
        print("[{}] {} -> {}  port {}/{}  ({})  rule {}  => {}".format(
            entry["time"][11:], entry["src"], entry["dst"], entry["port"],
            entry["protocol"], entry["type"], entry["rule"], entry["status"].upper()))

    alert = detector.analyse(entry)
    if alert:
        print("    !! SECURITY ALERT: {} - {}".format(alert["ip"], alert["message"]))
        if alert["level"] == "flood":      # auto-block flooding source
            firewall.add_rule(rules, alert["ip"], "Any", "Any", "Any", "Block",
                              "Auto-blocked (flood)", at_top=True)
            print("    !! {} added to the blocklist automatically.".format(alert["ip"]))


def show_rules():
    print("\n{:<8}{:<18}{:<16}{:<7}{:<9}{:<8}{}".format(
        "Rule", "Source", "Destination", "Port", "Protocol", "Action", "Note"))
    print("-" * 80)
    for r in rules:
        print("{:<8}{:<18}{:<16}{:<7}{:<9}{:<8}{}".format(
            r["id"], r["source"], r["destination"], r["port"], r["protocol"],
            r["action"], r["description"]))
    print("{:<8}{:<18}{:<16}{:<7}{:<9}{:<8}{}".format(
        "Default", "Any", "Any", "Any", "Any", "Block", "No rule matched"))


def ask_ip(prompt):
    while True:
        text = input(prompt).strip()
        if firewall.valid_ip(text):
            return text
        print("  Invalid IP address. Use a form like 192.168.1.10, 192.168.1.0/24 or Any.")


def ask_port(prompt, allow_any=True):
    while True:
        text = input(prompt).strip()
        if allow_any and text.lower() == "any":
            return "Any"
        if text.isdigit() and 0 < int(text) < 65536:
            return text
        print("  Port must be a number from 1 to 65535" + (" or Any." if allow_any else "."))


def ask_choice(prompt, options):
    while True:
        text = input(prompt).strip().lower()
        for o in options:
            if text == o.lower():
                return o
        print("  Please enter one of: " + ", ".join(options))


def add_rule_menu():
    print("\n--- Add Firewall Rule ---")
    src = ask_ip("Source IP (or Any / CIDR): ")
    dst = ask_ip("Destination IP (or Any / CIDR): ")
    port = ask_port("Port number (or Any): ")
    proto = ask_choice("Protocol (TCP / UDP / Any): ", ["TCP", "UDP", "Any"])
    action = ask_choice("Action (Allow / Block): ", ["Allow", "Block"])
    note = input("Description (optional): ").strip()
    rule = firewall.add_rule(rules, src, dst, port, proto, action, note)
    print("Rule {} added.".format(rule["id"]))


def delete_rule_menu():
    show_rules()
    rid = input("\nEnter rule ID to delete (e.g. R4): ").strip()
    print("Rule deleted." if firewall.delete_rule(rules, rid) else "Rule not found.")


def check_one_packet():
    print("\n--- Check a Packet ---")
    src = ask_ip("Source IP: ")
    dst = ask_ip("Destination IP: ")
    port = ask_port("Port number: ", allow_any=False)
    proto = ask_choice("Protocol (TCP / UDP): ", ["TCP", "UDP"])
    print()
    process_packet(traffic.make_packet(src, dst, port, proto))


def run_sample():
    print("\nRunning the 10 sample packets...\n")
    for p in traffic.SAMPLE_PACKETS:
        process_packet(p)


def run_random():
    text = input("How many packets to simulate? (default 20): ").strip()
    n = int(text) if text.isdigit() and int(text) > 0 else 20
    print()
    for _ in range(n):
        process_packet(traffic.random_packet())


def clear_data():
    log.clear()
    detector.__init__()
    open(LOG_FILE, "w").close()
    print("Log, alerts and counters cleared.")


MENU = """
===== NETWORK SECURITY AND FIREWALL MONITORING SYSTEM =====
 1. View firewall rules
 2. Add firewall rule
 3. Delete firewall rule
 4. Check a single packet
 5. Run sample traffic (10 packets)
 6. Simulate random traffic
 7. View security log
 8. View security alerts
 9. Network traffic dashboard
10. Clear log and alerts
 0. Exit
"""


def main():
    while True:
        print(MENU)
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            show_rules()
        elif choice == "2":
            add_rule_menu()
        elif choice == "3":
            delete_rule_menu()
        elif choice == "4":
            check_one_packet()
        elif choice == "5":
            run_sample()
        elif choice == "6":
            run_random()
        elif choice == "7":
            dashboard.print_log(log)
        elif choice == "8":
            dashboard.print_alerts(detector.alerts)
        elif choice == "9":
            dashboard.print_dashboard(log, detector.alerts)
        elif choice == "10":
            clear_data()
        elif choice == "0":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number from the menu.")


if __name__ == "__main__":
    main()
