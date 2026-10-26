from escaperoom.utils import solve_soc
from escaperoom.rooms.base import Room

# SOC Triage Desk: auth.log -> KEYPAD token


class SocRoom(Room):
    def __init__(self, data_dir):
        super().__init__("soc", "You enter the SOC Triage Desk.")
        self.data_path = f"{data_dir}/auth.log"

    def solve(self, state):
        result = solve_soc(self.data_path)
        state.tokens["KEYPAD"] = result["TOKEN[KEYPAD]"]
        return [f"{tag}={value}" for tag, value in result.items()]


if __name__ == "__main__":
    for tag, value in solve_soc("data/auth.log").items():
        print(f"{tag}={value}")
