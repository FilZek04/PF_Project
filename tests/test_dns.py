import base64
import codecs
import tempfile
import unittest
from pathlib import Path

from escaperoom.utils import decode_value, parse_config, solve_dns


def b64(text):
    return "b64:" + base64.b64encode(text.encode("utf-8")).decode("ascii")


def rot13_b64(text):
    return "rot13+b64:" + codecs.encode(base64.b64encode(text.encode("utf-8")).decode("ascii"), "rot13")


class DnsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "dns.cfg"

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.path

    def test_parse_config_skips_comments_and_strips_spaces(self):
        entries, malformed = parse_config(self.write([
            "# comment=ignored",
            "  hint1 = b64:abc  ",
            "env=lab",
            "no equals sign here",
        ]))
        self.assertEqual(entries, {"hint1": "b64:abc", "env": "lab"})
        self.assertEqual(malformed, 1)

    def test_parse_config_splits_value_at_first_equals(self):
        entries, _ = parse_config(self.write(["hint1=b64:Zm9v=="]))
        self.assertEqual(entries["hint1"], "b64:Zm9v==")

    def test_decode_b64(self):
        self.assertEqual(decode_value("b64:Mw=="), ("b64", "3"))

    def test_decode_rot13_b64_reverses_pipeline(self):
        sentence = "The code is not in the roots but near the closet."
        self.assertEqual(decode_value(rot13_b64(sentence)), ("rot13+b64", sentence))

    def test_rot13_payload_is_not_plain_b64(self):
        sentence = "The code is not in the roots but near the closet."
        payload = rot13_b64(sentence).split(":", 1)[1]
        try:
            _, text = decode_value("b64:" + payload)
        except ValueError:
            # Failing to decode also shows it is not plain Base64.
            return
        self.assertNotEqual(text, sentence)

    def test_decode_rejects_bad_values(self):
        bad = [
            "Mw==",
            "hex:4d",
            "b64:@@@@",
            "b64:" + base64.b64encode(b"\xff\xfe").decode("ascii"),
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    decode_value(value)

    def test_solve_dns_uses_token_tag_not_first_valid_hint(self):
        result = solve_dns(self.write([
            "# DNS hint configuration",
            " hint1 = " + b64("The apparent answer points to gateway."),
            "hint2=" + rot13_b64("The authoritative hint ends at relay."),
            "token_tag = " + b64("2"),
        ]))
        self.assertEqual(result["TOKEN[DNS]"], "relay")
        self.assertEqual(result["EVIDENCE[DNS].KEY"], "hint2")
        self.assertEqual(result["EVIDENCE[DNS].ENCODING"], "rot13+b64")
        self.assertEqual(result["EVIDENCE[DNS].DECODED_LINE"], "The authoritative hint ends at relay.")

    def test_solve_dns_without_token_tag_raises(self):
        with self.assertRaises(ValueError):
            solve_dns(self.write(["hint1=" + b64("The answer is relay.")]))

    def test_solve_dns_with_missing_hint_raises(self):
        with self.assertRaises(ValueError):
            solve_dns(self.write(["hint1=" + b64("The answer is relay."), "token_tag=" + b64("7")]))


if __name__ == "__main__":
    unittest.main()
