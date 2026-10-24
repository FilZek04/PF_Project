import re
from escaperoom.rooms.base import Room

# Regex for matching SAFE{a-b-c} where a, b, c are integers.
safe_re = re.compile(
    r"SAFE\s*\{\s*(\d+)\s*-\s*(\d+)\s*-\s*(\d+)\s*\}"
) 

def solve_vault(path):
    """ Searches vault_dump.txt for SAFE{a-b-c} and returns the values if a + b == c. """
    
    # open the vault file and read all lines 
    with open(path, 'r', encoding='utf-8') as f:    
        lines = f.readlines()  
        
    # Check each line for a SAFE pattern  
    for line in lines:    
        match = safe_re.search(line)
        
        # Extract the numbers if a match is found 
        if match:
            a = int(match.group(1))
            b = int(match.group(2))
            c = int(match.group(3))
        
            # Validate the checksum
            if a + b == c:
                return {
                    "TOKEN[SAFE]": f"{a}-{b}-{c}",
                    "EVIDENCE[SAFE].MATCH": f'"{match.group(0)}"',
                    "EVIDENCE[SAFE].CHECK": f"{a}+{b}={c}",
                }
    
    # If no valid SAFE pattern is found, return None
    return None
      
    

class VaultRoom(Room):
    def __init__(self, data_dir):
        super().__init__("vault", "You enter the Vault Corridor.")
        self.data_path = f"{data_dir}/vault_dump.txt"

    def solve(self, state):
        # Solve the vault puzzle and update the game state with the SAFE token if successful 
        result = solve_vault(self.data_path)
        
        # Stop if no valid SAFE code is found
        if result is None:
            return ["ACCESS DENIED"]
        
        # Save the SAFE token 
        state.tokens["SAFE"] = result["TOKEN[SAFE]"]

        return [f"{tag}={value}" for tag, value in result.items()]
    
# Run the file directly for testing
if __name__ == "__main__":
    for tag, value in solve_vault("data/vault_dump.txt").items():
        print(f"{tag}={value}") 

# Test teh regex and checksum    
    line = "SAFE{32-35-72}"
    match = safe_re.search(line)
    
    if match:
        a = int(match.group(1))
        b = int(match.group(2))
        c = int(match.group(3))
        
        if a + b == c:
            print("Test 1 passed.")
        else:
            print("Test 1 failed: checksum incorrect.")
    else:
        print("Test 1 failed: no match found.")