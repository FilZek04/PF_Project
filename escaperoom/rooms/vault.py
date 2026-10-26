from escaperoom.utils import solve_vault, SAFE_RE
from escaperoom.rooms.base import Room

class VaultRoom(Room):
    def __init__(self, data_dir):
        super().__init__("vault", "You enter the Vault Corridor.")
        self.data_path = f"{data_dir}/vault_dump.txt"

    def solve(self, state):
        # Solve the vault puzzle and update the game state with the SAFE token if successful 
        result = solve_vault(self.data_path)
        
        # Save the SAFE token 
        state.tokens["SAFE"] = result["TOKEN[SAFE]"]

        return [f"{tag}={value}" for tag, value in result.items()]
    
# Run the file directly for testing
if __name__ == "__main__":
    for tag, value in solve_vault("data/vault_dump.txt").items():
        print(f"{tag}={value}") 

# Test the regex and checksum    
    line = "SAFE{ 6 - 20 - 26 }"
    match = SAFE_RE.search(line)
    
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