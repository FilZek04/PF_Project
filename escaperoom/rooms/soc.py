import re

from escaperoom.utils import parseLogs
from escaperoom.rooms.base import Room

# SOC Triage Desk: auth.log -> KEYPAD token

LOG_PATTERN = re.compile(
    r"(?P<date>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ipv4>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) protocol 2"
)


def solve_soc(filepath):
    """Find the /24 with the most failed logins and build the KEYPAD token.

    Returns {transcript tag: value} for the token and its evidence.
    """
    _, malformedLines, failures, samples = parseLogs(filepath, LOG_PATTERN)
    if not failures:
        raise ValueError(f"no valid failed logins in {filepath}")

    totals = {subnet: sum(ips.values()) for subnet, ips in failures.items()}
    top24 = max(totals, key=totals.get)
    count = totals[top24]
    top_ip = max(failures[top24], key=failures[top24].get)
    lastOctet = top_ip.rsplit(".", 1)[1]

    return {
        "TOKEN[KEYPAD]": f"{lastOctet}{count}",
        "EVIDENCE[KEYPAD].TOP24": f"{top24}.0/24",
        "EVIDENCE[KEYPAD].COUNT": count,
        "EVIDENCE[KEYPAD].SAMPLE": samples[top24],
        "EVIDENCE[KEYPAD].MALFORMED_SKIPPED": malformedLines,
    }


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
