import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from escaperoom.engine import Engine
from escaperoom.transcript import Transcript


class EngineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.transcript = Transcript(str(self.dir / "run.txt"))
        self.engine = Engine(start="intro", data_dir=str(self.dir), transcript=self.transcript)

    def run_command(self, line):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            keep_going = self.engine.handle(line)
        return keep_going, out.getvalue()

    def test_unknown_start_room_raises(self):
        with self.assertRaises(ValueError):
            Engine(start="nowhere", data_dir=str(self.dir), transcript=self.transcript)

    def test_missing_data_dir_raises(self):
        with self.assertRaises(ValueError):
            Engine(start="intro", data_dir=str(self.dir / "missing"), transcript=self.transcript)

    def test_move_between_rooms(self):
        self.run_command("move soc")
        self.run_command("move dns")
        self.assertEqual(self.engine.state.current_room, "dns")

    def test_move_to_unknown_room_is_refused(self):
        _, out = self.run_command("move nowhere")
        self.assertEqual(self.engine.state.current_room, "intro")
        self.assertIn("nowhere", out)

    def test_unknown_command_keeps_running(self):
        keep_going, out = self.run_command("dance")
        self.assertTrue(keep_going)
        self.assertIn("Unknown command", out)

    def test_quit_stops_game(self):
        keep_going, _ = self.run_command("quit")
        self.assertFalse(keep_going)

    def test_missing_data_file_does_not_crash(self):
        self.run_command("move vault")
        keep_going, out = self.run_command("inspect vault_dump.txt")
        self.assertTrue(keep_going)
        self.assertIn("Could not analyse", out)

    def test_save_and_load_round_trip(self):
        self.engine.state.tokens["SAFE"] = "6-20-26"
        self.engine.state.inventory.add("SAFE")
        self.run_command("move vault")
        save = self.dir / "save.json"
        self.run_command(f"save {save}")
        self.run_command("move intro")
        self.engine.state.tokens.clear()
        self.run_command(f"load {save}")
        self.assertEqual(self.engine.state.current_room, "vault")
        self.assertEqual(self.engine.state.tokens, {"SAFE": "6-20-26"})
        self.assertEqual(self.engine.state.inventory, {"SAFE"})

    def test_load_malformed_save_keeps_state(self):
        save = self.dir / "bad.json"
        save.write_text(json.dumps({"current_room": "vault"}), encoding="utf-8")
        _, out = self.run_command(f"load {save}")
        self.assertEqual(self.engine.state.current_room, "intro")
        self.assertIn("malformed", out)


class TranscriptTests(unittest.TestCase):
    def test_each_tag_written_once_with_last_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.txt"
            transcript = Transcript(str(path))
            with contextlib.redirect_stdout(io.StringIO()):
                transcript.say("TOKEN[SAFE]=1-2-3")
                transcript.say("Some human text")
                transcript.say("TOKEN[SAFE]=6-20-26")
            transcript.write()
            lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual([line for line in lines if line.startswith("TOKEN[SAFE]=")], ["TOKEN[SAFE]=6-20-26"])
        self.assertIn("Some human text", lines)


if __name__ == "__main__":
    unittest.main()
