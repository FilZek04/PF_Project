from escaperoom.utils import solve_soc
from escaperoom.rooms.base import Room

# SOC Triage Desk: auth.log -> KEYPAD token


class SocRoom(Room):
    def __init__(self, data_dir):
        super().__init__("soc", "You enter the SOC Triage Desk.\nA cluttered screen shows failed SSH login attempts.")
        self.data_path = f"{data_dir}/auth.log"

    def solve(self, state):
        result = solve_soc(self.data_path)
        token = result["TOKEN[KEYPAD]"]
        count = result["EVIDENCE[KEYPAD].COUNT"]
        top24 = result["EVIDENCE[KEYPAD].TOP24"]
        state.tokens["KEYPAD"] = token
        # KEYPAD = "{L}{COUNT}", so the last octet is the token
        # without the count digits.
        last_octet = token[:-len(str(count))]
        top_ip = top24.removesuffix("0/24") + last_octet
        narration = [
            "[Room SOC] Parsing logs...",
            f"{count} failed attempts found in {top24}",
            f"Top IP is {top_ip} (last octet={last_octet})",
            f"Token formed: {token}",
            "",
        ]
        return narration + [f"{tag}={value}" for tag, value in result.items()]


if __name__ == "__main__":
    for tag, value in solve_soc("data/auth.log").items():
        print(f"{tag}={value}")
