import tempfile
import unittest
from pathlib import Path

from escaperoom.utils import SAFE_RE, solve_vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "vault_dump.txt"

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.path

    def test_regex_and_checksum(self):
        match = SAFE_RE.search("SAFE{ 6 - 20 - 26 }")
        self.assertIsNotNone(match)
        a, b, c = (int(group) for group in match.groups())
        self.assertEqual(a + b, c)

    def test_regex_tolerates_spacing(self):
        for text in ["SAFE{6-20-26}", "SAFE { 6 - 20 - 26 }", "SAFE{ 6-20 - 26 }"]:
            with self.subTest(text=text):
                self.assertEqual(SAFE_RE.search(text).groups(), ("6", "20", "26"))

    def test_regex_rejects_incomplete_candidates(self):
        for text in ["partialSAFE{3-4-}garbage", "SAFE{3-4}", "SAFE markers may contain spaces."]:
            with self.subTest(text=text):
                self.assertIsNone(SAFE_RE.search(text))

    def test_solve_vault_finds_only_valid_candidate_and_keeps_spacing(self):
        result = solve_vault(self.write([
            "SAFE{ 29-18-44 }",
            "partialSAFE{3-4-}garbage",
            "SAFE { 6 - 20 - 26 }",
            "SAFE{5-6-12} maybe",
        ]))
        self.assertEqual(result["TOKEN[SAFE]"], "6-20-26")
        self.assertEqual(result["EVIDENCE[SAFE].MATCH"], '"SAFE { 6 - 20 - 26 }"')
        self.assertEqual(result["EVIDENCE[SAFE].CHECK"], "6+20=26")

    def test_solve_vault_checks_every_candidate_on_a_line(self):
        result = solve_vault(self.write(["SAFE{9-9-1} noise SAFE { 4 - 5 - 9 }"]))
        self.assertEqual(result["TOKEN[SAFE]"], "4-5-9")

    def test_solve_vault_without_valid_candidate_raises(self):
        with self.assertRaises(ValueError):
            solve_vault(self.write(["SAFE{1-2-4}", "SAFE{30-7-53}"]))

    def test_solve_vault_with_two_valid_candidates_raises(self):
        with self.assertRaises(ValueError):
            solve_vault(self.write(["SAFE{1-2-3}", "SAFE{2-2-4}"]))


if __name__ == "__main__":
    unittest.main()
