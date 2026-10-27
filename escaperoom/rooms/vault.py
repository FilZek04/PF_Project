from escaperoom.utils import solve_vault
from escaperoom.rooms.base import Room

class VaultRoom(Room):
    def __init__(self, data_dir):
        super().__init__("vault", "You enter the Vault Corridor.\nA noisy dump scrolls past. Somewhere a SAFE{a-b-c} hides.")
        self.data_path = f"{data_dir}/vault_dump.txt"

    def solve(self, state):
        result = solve_vault(self.data_path)
        state.tokens["SAFE"] = result["TOKEN[SAFE]"]

        # Human-readable lines shown before the tagged transcript lines.
        candidate = result["EVIDENCE[SAFE].MATCH"].strip('"')
        narration = [
            "[Room Vault] Scanning dump...",
            f"Found candidate: {candidate}",
            f"Checksum: {result['EVIDENCE[SAFE].CHECK']} (OK)",
            "",
        ]
        return narration + [f"{tag}={value}" for tag, value in result.items()]
    
# Run the file directly for testing.
if __name__ == "__main__":
    for tag, value in solve_vault("data/vault_dump.txt").items():
        print(f"{tag}={value}") 
