from escaperoom.utils import solve_vault
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
