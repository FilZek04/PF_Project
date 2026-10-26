import json
from collections import defaultdict,deque
import ipaddress
from datetime import datetime
import shlex
import os
import re
import base64
import codecs
import hmac
import hashlib

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

def createProcessesGraph(parsedJson) : 
    children = defaultdict(list)
    cmd = {}
    roots = set()
    for rec in parsedJson :
        if rec["pid"] in cmd and cmd[rec["pid"]] != rec["cmd"] :
            raise ValueError(f"inconsistent cmd for pid {rec['pid']}")
        children[rec["ppid"]].append(rec["pid"])
        cmd[rec["pid"]] = rec["cmd"]
        if rec["ppid"] == 0 :
            roots.add(rec["pid"])
    if len(roots) != 1 :
        raise ValueError(f"expected exactly one root process, found {len(roots)}")
    return children,cmd,roots.pop()

def is_exfil(command):
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    
    PATTERN = r"[^@\s:]+@[^@\s:]+:\S+"

    program = os.path.basename(parts[0])
    
    if program == 'curl' :
        pairs = list(zip(parts, parts[1:]))
        return ("-X","POST") in pairs and ("-d","@/tmp/x.tgz") in pairs
    
    elif program == 'scp' :
        return "/tmp/x.tgz" in parts and any(re.fullmatch(PATTERN, p) for p in parts)                                                                  

    return False

def BFS(root,children,is_target) :
    parent = {root : None}
    queue = deque([root])
    while queue : 
        node = queue.popleft()
        if is_target(node) :
            path = []
            while node is not None : 
                path.append(node)
                node = parent[node]
            return path[::-1]
        for child in children.get(node,[]) : 
            if child not in parent : 
                parent[child] = node
                queue.append(child)
    return None

def DFS(node,children,is_target,visited): 
    visited.add(node)
    if is_target(node) :
        return [node]
    for child in children.get(node,[]):
        if child not in visited : 
            result = DFS(child,children,is_target,visited)
            if result is not None : 
                return [node] + result
    return None



         


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

LOG_PATTERN = re.compile(
    r"(?P<date>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ipv4>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) protocol 2"
)


def solve_soc(filepath):
    """Find the /24 with the most failed logins and build the KEYPAD token.

    Returns {transcript tag: value} for the token and its evidence.
    """
    _, malformedLines, failures, samples = parseLogs(filepath, LOG_PATTERN)
    if not failures:
        raise ValueError(f"no valid failed logins in {filepath}")

    totals = {subnet: sum(ips.values()) for subnet, ips in failures.items()}
    top24 = max(totals, key=totals.get)
    count = totals[top24]
    top_ip = max(failures[top24], key=failures[top24].get)
    lastOctet = top_ip.rsplit(".", 1)[1]

    return {
        "TOKEN[KEYPAD]": f"{lastOctet}{count}",
        "EVIDENCE[KEYPAD].TOP24": f"{top24}.0/24",
        "EVIDENCE[KEYPAD].COUNT": count,
        "EVIDENCE[KEYPAD].SAMPLE": samples[top24],
        "EVIDENCE[KEYPAD].MALFORMED_SKIPPED": malformedLines,
    }

# Helpers for the DNS Room

def parseConfig(filepath):
    """Read key=value lines, skipping # comments.

    Returns (entries, malformedLines) where entries = {key: value},
    with spaces stripped around keys and values, and malformedLines
    counts non-comment lines without '='.
    """
    entries = {}
    malformedLines = 0
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                malformedLines += 1
                continue
            entries[key.strip()] = value.strip()
    return entries, malformedLines

def decodeValue(value):
    """Decode '<encoding>:<payload>' and return (encoding, text).

    Supports b64 and rot13+b64. Raises ValueError for an unknown
    encoding, bad Base64, or bytes that are not valid UTF-8.
    """
    encoding, sep, payload = value.partition(":")
    if not sep:
        raise ValueError(f"no encoding prefix in {value!r}")
    if encoding == "b64":
        b64text = payload
    elif encoding == "rot13+b64":
        b64text = codecs.decode(payload, "rot13")
    else:
        raise ValueError(f"unsupported encoding {encoding!r}")
    raw = base64.b64decode(b64text, validate=True)
    return encoding, raw.decode("utf-8")

def solve_dns(filepath):

    entries, _ = parseConfig(filepath)
    if "token_tag" not in entries:
        raise ValueError(f"no token_tag in {filepath}")

    _, tag = decodeValue(entries["token_tag"])
    key = f"hint{tag}"
    if key not in entries:
        raise ValueError(f"token_tag points to missing {key}")

    encoding, sentence = decodeValue(entries[key])
    token = sentence.rsplit(" ", 1)[-1].removesuffix(".")

    return {
        "TOKEN[DNS]": token,
        "EVIDENCE[DNS].KEY": key,
        "EVIDENCE[DNS].ENCODING": encoding,
        "EVIDENCE[DNS].DECODED_LINE": sentence,
    }

# helper functions for vault room

# Regex for matching SAFE{a-b-c} where a, b, c are integers.
SAFE_RE = re.compile(
    r"SAFE\s*\{\s*(\d+)\s*-\s*(\d+)\s*-\s*(\d+)\s*\}"
) 

def solve_vault(path):
    """ Searches vault_dump.txt for SAFE{a-b-c} and returns the values if a + b == c. """
    
    valid = []
    # open the vault file and read all lines 
    with open(path, 'r', encoding='utf-8') as f:    
        lines = f.readlines()  
        
    # Check each line for a SAFE pattern  
    for line in lines:    
        
        # Extract the numbers if a match is found 
        for match in SAFE_RE.finditer(line):
            a = int(match.group(1))
            b = int(match.group(2))
            c = int(match.group(3))
        
            # Validate the checksum
            if a + b == c:
                valid.append({
                    "TOKEN[SAFE]": f"{a}-{b}-{c}",
                    "EVIDENCE[SAFE].MATCH": f'"{match.group(0)}"',
                    "EVIDENCE[SAFE].CHECK": f"{a}+{b}={c}",
                })
    
    if len(valid) != 1:
        raise ValueError(f"expected exactly one valid SAFE code in {path}, found {len(valid)}")
    return valid[0]

# helper functions for final gate

def parseGate(filepath):
    entries, _ = parseConfig(filepath)
    missing = [k for k in ("group_id", "token_order", "hmac_key") if not entries.get(k)]
    if missing:
        raise ValueError(f"missing {', '.join(missing)} in {filepath}")
    order = [name.strip() for name in entries["token_order"].split(",")]
    if len(order) != 4 or len(set(order)) != 4:
        raise ValueError(f"token_order must list four different tokens, got {entries['token_order']!r}")
    return entries["group_id"], order, entries["hmac_key"]

def buildMessage(group_id, order, tokens):
    missing = [name for name in order if name not in tokens]
    if missing:
        raise ValueError(f"the gate stays shut, missing tokens: {', '.join(missing)}")
    return f"{group_id}|" + "-".join(tokens[name] for name in order)

def computeHmac(key, message):
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
