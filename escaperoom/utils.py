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

# Helpers for the Malware Room

def parse_file(filepath) :
    """Read one JSON record per line, skipping blank lines.

    Returns (good_lines, bad_lines): the valid records and the number
    of lines that were broken JSON or had the wrong shape.
    """
    good_lines,bad_lines = [], 0
    with open(filepath,"r", encoding = "utf-8") as f :  
        for line in f : 
            line = line.strip()
            if not line :
                continue 
            try :  
                obj = json.loads(line)
            except json.JSONDecodeError : 
                bad_lines += 1 
                continue
            if not is_valid(obj) : 
                bad_lines += 1
                continue
            good_lines.append(obj)
        return good_lines,bad_lines

def is_valid(obj) :
    """Check the record has exactly pid, ppid (int) and cmd (str)."""
    expected= {"pid" : int, "ppid" : int, "cmd" : str}
    if not isinstance(obj,dict) :
        return False
    if obj.keys() != expected.keys() :
        return False
    # bool is a subclass of int, so True would otherwise pass as a pid.
    return all (
        isinstance(obj[k],t) and not isinstance(obj[k],bool)
        for k,t in expected.items()
    )

def create_processes_graph(parsed_json) :
    """Build the process tree from the valid records.

    Returns (children, cmd, root) where children = {ppid: [pids]},
    cmd = {pid: command} and root is the only process with ppid 0.
    """
    children = defaultdict(list)
    cmd = {}
    roots = set()
    for rec in parsed_json :
        # A pid may appear twice, but only with the same command.
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
    """Return True if curl or scp uploads /tmp/x.tgz."""
    # Split like a shell so quoted arguments stay together; unclosed
    # quotes raise ValueError, and such a command is not exfiltration.
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False

    # Remote scp target, e.g. user@host:path.
    pattern = r"[^@\s:]+@[^@\s:]+:\S+"

    program = os.path.basename(parts[0])
    # Unwrap sh -c '...' and check the command inside the quotes.
    if program in ("sh", "bash") and len(parts) > 2 and parts[1] == "-c":
        return is_exfil(parts[2])

    if program == 'curl' :
        # Pair each argument with the next one to find flag/value pairs.
        pairs = list(zip(parts, parts[1:]))
        return ("-X","POST") in pairs and ("-d","@/tmp/x.tgz") in pairs
    
    elif program == 'scp' :
        return "/tmp/x.tgz" in parts and any(re.fullmatch(pattern, p) for p in parts)                                                                  

    return False

def bfs(root,children,is_target) :
    """Return the shortest path from root to a target, or None."""
    # parent doubles as the visited set and lets us rebuild the path.
    parent = {root : None}
    queue = deque([root])
    while queue :
        node = queue.popleft()
        if is_target(node) :
            # Walk back via parents, then reverse so root comes first.
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

def dfs(node,children,is_target,visited):
    """Return a depth-first path from node to a target, or None.

    visited is shared across the recursion so cycles are not followed.
    """
    visited.add(node)
    if is_target(node) :
        return [node]
    for child in children.get(node,[]):
        if child not in visited : 
            result = dfs(child,children,is_target,visited)
            if result is not None :
                # Prepend this node to the path found below it.
                return [node] + result
    return None



         


# Helpers for the SOC Room

def parse_logs(filepath, pattern):
    """Validate each log line and group failed logins by /24 subnet.

    pattern must define the named groups: date, status, ipv4.
    Returns (wellformed_lines, malformed_lines, failures, samples) where
    failures = {subnet: {ip: failed count}} and
    samples  = {subnet: first valid failed line}.
    """
    malformed_lines = 0
    wellformed_lines = 0
    failures = {}
    samples = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            # Strip only the newline: stray spaces must still fail.
            line = line.strip("\n")
            m = pattern.fullmatch(line)
            if not m:
                malformed_lines += 1
                continue
            # The regex only checks the shape; also check the values,
            # e.g. month 13 or an octet above 255.
            try:
                datetime.fromisoformat(m["date"])
                ipaddress.IPv4Address(m["ipv4"])
            except ValueError:
                malformed_lines += 1
                continue
            wellformed_lines += 1
            if m["status"] == "Failed":
                ip = m["ipv4"]
                # The /24 subnet is the first three octets.
                subnet = ip.rsplit(".", 1)[0]
                # setdefault only stores the first failed line seen.
                samples.setdefault(subnet, line)
                inner = failures.setdefault(subnet, {})
                inner[ip] = inner.get(ip, 0) + 1
    return wellformed_lines, malformed_lines, failures, samples

# One complete sshd line; parse_logs reads date, status and ipv4.
LOG_PATTERN = re.compile(
    r"(?P<date>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ipv4>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) protocol 2"
)


def solve_soc(filepath):
    """Find the /24 with the most failed logins; build KEYPAD.

    Returns {transcript tag: value} for the token and its evidence.
    """
    _, malformed_lines, failures, samples = parse_logs(filepath, LOG_PATTERN)
    if not failures:
        raise ValueError(f"no valid failed logins in {filepath}")

    totals = {subnet: sum(ips.values()) for subnet, ips in failures.items()}
    top24 = max(totals, key=totals.get)
    count = totals[top24]
    # Token = last octet of the top IP in that /24 + the /24 total.
    top_ip = max(failures[top24], key=failures[top24].get)
    last_octet = top_ip.rsplit(".", 1)[1]

    return {
        "TOKEN[KEYPAD]": f"{last_octet}{count}",
        "EVIDENCE[KEYPAD].TOP24": f"{top24}.0/24",
        "EVIDENCE[KEYPAD].COUNT": count,
        "EVIDENCE[KEYPAD].SAMPLE": samples[top24],
        "EVIDENCE[KEYPAD].MALFORMED_SKIPPED": malformed_lines,
    }

# Helpers for the DNS Room

def parse_config(filepath):
    """Read key=value lines, skipping # comments.

    Returns (entries, malformed_lines) where entries = {key: value},
    with spaces stripped around keys and values, and malformed_lines
    counts non-comment lines without '='.
    """
    entries = {}
    malformed_lines = 0
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Split at the first '=' only: Base64 values can end in '='.
            key, sep, value = line.partition("=")
            if not sep:
                malformed_lines += 1
                continue
            # A repeated key keeps its last value.
            entries[key.strip()] = value.strip()
    return entries, malformed_lines

def decode_value(value):
    """Decode '<encoding>:<payload>' and return (encoding, text).

    Supports b64 and rot13+b64. Raises ValueError for an unknown
    encoding, bad Base64, or bytes that are not valid UTF-8.
    """
    encoding, sep, payload = value.partition(":")
    if not sep:
        raise ValueError(f"no encoding prefix in {value!r}")
    if encoding == "b64":
        b64_text = payload
    elif encoding == "rot13+b64":
        # Undo the encodings in reverse order: ROT13 first, then Base64.
        b64_text = codecs.decode(payload, "rot13")
    else:
        raise ValueError(f"unsupported encoding {encoding!r}")
    # validate=True rejects characters outside the Base64 alphabet.
    raw = base64.b64decode(b64_text, validate=True)
    return encoding, raw.decode("utf-8")

def solve_dns(filepath):
    """Decode the hint chosen by token_tag and take its last word.

    Returns {transcript tag: value} for the token and its evidence.
    """
    entries, _ = parse_config(filepath)
    if "token_tag" not in entries:
        raise ValueError(f"no token_tag in {filepath}")

    _, tag = decode_value(entries["token_tag"])
    key = f"hint{tag}"
    if key not in entries:
        raise ValueError(f"token_tag points to missing {key}")

    encoding, sentence = decode_value(entries[key])
    token = sentence.rsplit(" ", 1)[-1].removesuffix(".")

    return {
        "TOKEN[DNS]": token,
        "EVIDENCE[DNS].KEY": key,
        "EVIDENCE[DNS].ENCODING": encoding,
        "EVIDENCE[DNS].DECODED_LINE": sentence,
    }

# Helpers for the Vault Room

# Regex for matching SAFE{a-b-c} where a, b, c are integers.
SAFE_RE = re.compile(
    r"SAFE\s*\{\s*(\d+)\s*-\s*(\d+)\s*-\s*(\d+)\s*\}"
)

def solve_vault(path):
    """Find the one SAFE{a-b-c} in the dump where a + b == c.

    Returns {transcript tag: value} for the token and its evidence.
    """
    valid = []
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:

        # finditer, not search: one line can hold several candidates.
        for match in SAFE_RE.finditer(line):
            a = int(match.group(1))
            b = int(match.group(2))
            c = int(match.group(3))

            if a + b == c:
                valid.append({
                    "TOKEN[SAFE]": f"{a}-{b}-{c}",
                    "EVIDENCE[SAFE].MATCH": f'"{match.group(0)}"',
                    "EVIDENCE[SAFE].CHECK": f"{a}+{b}={c}",
                })
    
    if len(valid) != 1:
        raise ValueError(f"expected exactly one valid SAFE code in {path}, found {len(valid)}")
    return valid[0]

# Helpers for the Final Gate

def parse_gate(filepath):
    """Return (group_id, token_order as a list, hmac_key)."""
    entries, _ = parse_config(filepath)
    missing = [k for k in ("group_id", "token_order", "hmac_key") if not entries.get(k)]
    if missing:
        raise ValueError(f"missing {', '.join(missing)} in {filepath}")
    order = [name.strip() for name in entries["token_order"].split(",")]
    if len(order) != 4 or len(set(order)) != 4:
        raise ValueError(f"token_order must list four different tokens, got {entries['token_order']!r}")
    return entries["group_id"], order, entries["hmac_key"]

def build_message(group_id, order, tokens):
    """Return MSG = group_id|token1-token2-... in token_order."""
    missing = [name for name in order if name not in tokens]
    if missing:
        raise ValueError(f"the gate stays shut, missing tokens: {', '.join(missing)}")
    return f"{group_id}|" + "-".join(tokens[name] for name in order)

def compute_hmac(key, message):
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
