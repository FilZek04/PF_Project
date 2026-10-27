from escaperoom.utils import solve_dns
from escaperoom.rooms.base import Room

# DNS Closet: dns.cfg -> DNS token

class DnsRoom(Room):
    def __init__(self, data_dir):
        super().__init__("dns", "You enter the DNS Closet.\nThe walls are covered with scribbled key=value pairs.")
        self.data_path = f"{data_dir}/dns.cfg"

    def solve(self, state):
        result = solve_dns(self.data_path)
        state.tokens["DNS"] = result["TOKEN[DNS]"]
        narration = [
            "[Room DNS] Decoding hints...",
            f'Decoded line: "{result["EVIDENCE[DNS].DECODED_LINE"]}"',
            f"Token formed: {result['TOKEN[DNS]']}",
            "",
        ]
        return narration + [f"{tag}={value}" for tag, value in result.items()]


if __name__ == "__main__":
    for tag, value in solve_dns("data/dns.cfg").items():
        print(f"{tag}={value}")
