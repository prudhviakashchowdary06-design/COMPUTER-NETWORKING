"""Firewall rules: load, save, add, delete and match packets."""
import json
import ipaddress
import os

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
DEFAULT_ACTION = "Block"   # packets that match no rule are blocked


def load_rules():
    try:
        with open(RULES_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def next_rule_id(rules):
    nums = [int(r["id"][1:]) for r in rules if r["id"][1:].isdigit()]
    return "R" + str(max(nums, default=0) + 1)


def valid_ip(text):
    if text.lower() == "any":
        return True
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def add_rule(rules, source, destination, port, protocol, action, description="", at_top=False):
    rule = {
        "id": next_rule_id(rules),
        "source": source,
        "destination": destination,
        "port": str(port),
        "protocol": protocol.upper() if protocol.lower() != "any" else "Any",
        "action": action.capitalize(),
        "description": description,
    }
    if at_top:
        rules.insert(0, rule)
    else:
        rules.append(rule)
    save_rules(rules)
    return rule


def delete_rule(rules, rule_id):
    for r in rules:
        if r["id"].lower() == rule_id.lower():
            rules.remove(r)
            save_rules(rules)
            return True
    return False


def _ip_match(rule_ip, packet_ip):
    if rule_ip.lower() == "any":
        return True
    return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip, strict=False)


def check_packet(packet, rules):
    """Return (rule_id, action) of the first matching rule; Default if none."""
    for r in rules:
        if not _ip_match(r["source"], packet["src"]):
            continue
        if not _ip_match(r["destination"], packet["dst"]):
            continue
        if r["port"].lower() != "any" and int(r["port"]) != packet["port"]:
            continue
        if r["protocol"].lower() != "any" and r["protocol"].upper() != packet["protocol"].upper():
            continue
        return r["id"], r["action"]
    return "Default", DEFAULT_ACTION
