from escaperoom.utils import parseConfig, decodeValue
from escaperoom.rooms.base import Room

# DNS Closet: dns.cfg -> DNS token

def solve_dns(filepath):

    entries, _ = parseConfig(filepath)
    if "token_tag" not in entries:
        raise ValueError(f"no token_tag in {filepath}")

    _, tag = decodeValue(entries["token_tag"])
    key = f"hint{tag}"
    if key not in entries:
        raise ValueError(f"token_tag points to missing {key}")

    encoding, sentence = decodeValue(entries[key])
    token = sentence.rsplit(" ", 1)[-1].removesuffix(".")

    return {
        "TOKEN[DNS]": token,
        "EVIDENCE[DNS].KEY": key,
        "EVIDENCE[DNS].ENCODING": encoding,
        "EVIDENCE[DNS].DECODED_LINE": sentence,
    }

class DnsRoom(Room):
    def __init__(self, data_dir):
        super().__init__("dns", "You enter the DNS Closet.")
        self.data_path = f"{data_dir}/dns.cfg"

    def solve(self, state):
        result = solve_dns(self.data_path)
        state.tokens["DNS"] = result["TOKEN[DNS]"]
        return [f"{tag}={value}" for tag, value in result.items()]


        

if __name__ == "__main__":
    for tag, value in solve_dns("data/dns.cfg").items():
        print(f"{tag}={value}")
