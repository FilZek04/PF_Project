import json
import ipaddress
from datetime import datetime

# malware room helper functions

def parseFile(filepath) :

    goodLines,badLines = [], 0
    with open(filepath,"r", encoding = "utf-8") as f :  
        for line in f : 
            line = line.strip()
            if not line :
                continue 
            try :  
                obj = json.loads(line)
            except json.JSONDecodeError : 
                badLines += 1 
                continue
            if not isValid(obj) : 
                badLines += 1
                continue
            goodLines.append(obj)
        return goodLines,badLines

def isValid(obj) : 

    expected= {"pid" : int, "ppid" : int, "cmd" : str}
    if not isinstance(obj,dict) : 
        return False
    if obj.keys() != expected.keys() : 
        return False
    return all (
        isinstance(obj[k],t) and not isinstance(obj[k],bool)
        for k,t in expected.items()
    )

# Helpers for the SOC Room

def parseLogs(filepath, pattern):
    """Validate each log line and group failed logins by /24 subnet.

    pattern must define the named groups: date, status, ipv4.
    Returns (wellformedLines, malformedLines, failures, samples) where
    failures = {subnet: {ip: failed count}} and
    samples  = {subnet: first valid failed line}.
    """
    malformedLines = 0
    wellformedLines = 0
    failures = {}
    samples = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip("\n")
            m = pattern.fullmatch(line)
            if not m:
                malformedLines += 1
                continue
            try:
                datetime.fromisoformat(m["date"])
                ipaddress.IPv4Address(m["ipv4"])
            except ValueError:
                malformedLines += 1
                continue
            wellformedLines += 1
            if m["status"] == "Failed":
                ip = m["ipv4"]
                subnet = ip.rsplit(".", 1)[0]
                samples.setdefault(subnet, line)
                inner = failures.setdefault(subnet, {})
                inner[ip] = inner.get(ip, 0) + 1
    return wellformedLines, malformedLines, failures, samples
