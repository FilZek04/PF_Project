import hashlib
import hmac
import re
import tempfile
import unittest
from pathlib import Path

from escaperoom.utils import build_message, compute_hmac, parse_gate

TOKENS = {"KEYPAD": "4217", "DNS": "closet", "SAFE": "6-20-26", "PID": "136"}


class FinalGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "final_gate.txt"

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.path

    def test_parse_gate_reads_all_fields(self):
        group_id, order, key = parse_gate(self.write([
            "group_id=group99",
            "token_order=DNS, SAFE, PID, KEYPAD",
            "hmac_key=secret",
        ]))
        self.assertEqual(group_id, "group99")
        self.assertEqual(order, ["DNS", "SAFE", "PID", "KEYPAD"])
        self.assertEqual(key, "secret")

    def test_parse_gate_rejects_missing_fields(self):
        with self.assertRaises(ValueError):
            parse_gate(self.write(["group_id=group99", "token_order=DNS,SAFE,PID,KEYPAD"]))

    def test_parse_gate_rejects_bad_token_order(self):
        for order in ["DNS,SAFE,PID", "DNS,SAFE,PID,PID", "DNS,SAFE,PID,KEYPAD,EXTRA"]:
            with self.subTest(order=order):
                with self.assertRaises(ValueError):
                    parse_gate(self.write(["group_id=g", f"token_order={order}", "hmac_key=k"]))

    def test_build_message_follows_token_order(self):
        self.assertEqual(
            build_message("group99", ["DNS", "PID", "KEYPAD", "SAFE"], TOKENS),
            "group99|closet-136-4217-6-20-26",
        )
        self.assertEqual(
            build_message("group99", ["KEYPAD", "PID", "SAFE", "DNS"], TOKENS),
            "group99|4217-136-6-20-26-closet",
        )

    def test_build_message_with_missing_token_raises(self):
        tokens = dict(TOKENS)
        del tokens["SAFE"]
        with self.assertRaises(ValueError):
            build_message("group99", ["DNS", "PID", "KEYPAD", "SAFE"], tokens)

    def test_compute_hmac_known_vector(self):
        self.assertEqual(
            compute_hmac("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )

    def test_compute_hmac_is_lowercase_hex_sha256(self):
        message = "group99|closet-136-4217-6-20-26"
        digest = compute_hmac("secret", message)
        self.assertRegex(digest, re.compile(r"^[0-9a-f]{64}$"))
        self.assertEqual(digest, hmac.new(b"secret", message.encode("utf-8"), hashlib.sha256).hexdigest())

    def test_compute_hmac_changes_with_message(self):
        self.assertNotEqual(compute_hmac("k", "g|a-b-c-d"), compute_hmac("k", "g|b-a-c-d"))


if __name__ == "__main__":
    unittest.main()
