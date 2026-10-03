import json
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