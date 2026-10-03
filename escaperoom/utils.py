# malware room helper functions 

def parseFile(filepath) :

    goodLines,badLines = [], 0
    with open("proc_tree.json","r", encoding = "utf-8") as f :  
        for line in f : 
            line.strip()
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

    expectedKey = {"pid","ppid","cmd"}
    if not isinstance(obj,dict) : 
        return False
    if set(obj.keys()) != expectedKey : 
        return False
    return True