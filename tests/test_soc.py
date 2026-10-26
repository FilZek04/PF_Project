import tempfile
import unittest
from pathlib import Path

from escaperoom.utils import LOG_PATTERN, parseLogs, solve_soc


def failed(ip, host="lab1"):
    return f"2026-10-05T09:00:03Z {host} sshd[2065]: Failed password for admin from {ip} port 40693 protocol 2"


def accepted(ip):
    return f"2026-10-05T09:00:03Z lab1 sshd[2065]: Accepted password for admin from {ip} port 40693 protocol 2"


class SocTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "auth.log"

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.path

    def test_valid_failed_line_is_grouped_by_subnet(self):
        line = failed("203.0.113.42")
        wellformed, malformed, failures, samples = parseLogs(self.write([line]), LOG_PATTERN)
        self.assertEqual(wellformed, 1)
        self.assertEqual(malformed, 0)
        self.assertEqual(failures, {"203.0.113": {"203.0.113.42": 1}})
        self.assertEqual(samples, {"203.0.113": line})

    def test_accepted_lines_are_not_failures(self):
        wellformed, malformed, failures, _ = parseLogs(self.write([accepted("203.0.113.42")]), LOG_PATTERN)
        self.assertEqual(wellformed, 1)
        self.assertEqual(malformed, 0)
        self.assertEqual(failures, {})

    def test_malformed_lines_are_skipped_and_counted(self):
        bad = [
            "2026-10-05T09:00:00Z lab1 sshd: Failed password for root from 203.0.113.42 port 50221 protocol 2",
            "2026-10-05T09:00:00Z sshd[2065]: Failed password for root from 203.0.113.42 port 50221 protocol 2",
            "2026-10-05T09:00:00Z lab1 sshd[2065]: Failed password for root from 203.0.113.42",
            "2026-10-05T09:00:00Z lab1 sshd[2065]: Failed password for root from 203.0.113.999 port 50432 protocol 2",
            "2026-13-45T09:00:00Z lab1 sshd[2065]: Failed password for root from 203.0.113.42 port 50432 protocol 2",
            "2026-10-05T09:00:00Z lab1 sshd[abc]: Failed password for root from 203.0.113.42 port 50432 protocol 2",
            "2026-10-05T09:00:00Z lab1 sshd[2065]: Failed password for root from 203.0.113.42 port 50432 protocol 1",
            "complete garbage",
        ]
        for line in bad:
            with self.subTest(line=line):
                wellformed, malformed, failures, _ = parseLogs(self.write([line]), LOG_PATTERN)
                self.assertEqual(wellformed, 0)
                self.assertEqual(malformed, 1)
                self.assertEqual(failures, {})

    def test_solve_soc_builds_keypad_from_winning_subnet(self):
        lines = [
            failed("198.51.100.5"),
            failed("203.0.113.42"),
            failed("203.0.113.7"),
            failed("203.0.113.42"),
            failed("198.51.100.5"),
            failed("203.0.113.42"),
            accepted("203.0.113.42"),
            "broken line",
        ]
        result = solve_soc(self.write(lines))
        self.assertEqual(result["TOKEN[KEYPAD]"], "424")
        self.assertEqual(result["EVIDENCE[KEYPAD].TOP24"], "203.0.113.0/24")
        self.assertEqual(result["EVIDENCE[KEYPAD].COUNT"], 4)
        self.assertEqual(result["EVIDENCE[KEYPAD].SAMPLE"], failed("203.0.113.42"))
        self.assertEqual(result["EVIDENCE[KEYPAD].MALFORMED_SKIPPED"], 1)

    def test_solve_soc_without_failures_raises(self):
        with self.assertRaises(ValueError):
            solve_soc(self.write([accepted("203.0.113.42")]))


if __name__ == "__main__":
    unittest.main()
