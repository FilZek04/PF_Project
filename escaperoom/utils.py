import json
from collections import defaultdict,deque
import ipaddress
from datetime import datetime
import shlex
import os
import re

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
    root = None
    for rec in parsedJson : 
        children[rec["ppid"]].append(rec["pid"])
        cmd[rec["pid"]] = rec["cmd"]
        if rec["ppid"] == 0 : 
            root = rec["pid"]
    return children,cmd,root

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
