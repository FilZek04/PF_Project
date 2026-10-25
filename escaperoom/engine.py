import json
from dataclasses import dataclass, field
from pathlib import Path
from escaperoom.rooms.base import Room
from escaperoom.rooms.malware import MalwareRoom
from escaperoom.rooms.soc import SocRoom
from escaperoom.rooms.dns import DnsRoom
from escaperoom.rooms.vault import VaultRoom

def build_rooms(data_dir: Path) -> dict[str, Room]:
    return {
        "intro": Room("intro", "You are in the Intro Lobby.\nA terminal blinks in the corner."),
        "soc": SocRoom(data_dir),
        "dns": DnsRoom(data_dir),
        "vault": VaultRoom(data_dir),
        "malware": MalwareRoom(data_dir),
        "final": Room("final", "You stand before the Final Gate."),
    }

@dataclass
class GameState:
    current_room: str = "intro"
    inventory: set[str] = field(default_factory=set)
    tokens: dict[str, str] = field(default_factory=dict)


ITEMS = {
    "soc": "auth.log",
    "dns": "dns.cfg",
    "vault": "vault_dump.txt",
    "malware": "proc_tree.jsonl",
    "final": "gate",
}

EXITS = {
    "intro": ["soc", "dns", "vault", "malware", "final"],
}


class Engine:
    def __init__(self, start: str, data_dir: str, transcript):
        self.transcript = transcript
        self.data_dir = Path(data_dir)
        if not self.data_dir.is_dir():
            raise ValueError(f"data directory '{data_dir}' not found")
        self.rooms = build_rooms(self.data_dir)
        if start not in self.rooms:
            raise ValueError(f"unknown start room '{start}'")
        self.state = GameState(current_room=start)
        self.commands = {
            "look": self.cmd_look,
            "move": self.cmd_move,
            "inspect": self.cmd_inspect,
            "use": self.cmd_use,
            "inventory": self.cmd_inventory,
            "hint": self.cmd_hint,
            "save": self.cmd_save,
            "load": self.cmd_load,
            "help": self.cmd_help,
            "quit": self.cmd_quit,
        }

    def run(self) -> None:
        self.transcript.say("[Game] Cyber Escape Room started. Type 'help' for commands.")
        try:
            while True:
                try:
                    line = input("> ")
                except EOFError:
                    break
                self.transcript.echo(line)
                if not self.handle(line):
                    break
        finally:
            self.transcript.write()

    def handle(self, line: str) -> bool:
        """Dispatch one command. Returns False when the game should stop."""
        parts = line.strip().split(maxsplit=1)
        if not parts:
            return True
        verb = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        handler = self.commands.get(verb)
        if handler is None:
            self.transcript.say(f"Unknown command '{verb}'. Type 'help'.")
            return True
        return handler(arg) is not False

    def _describe(self) -> str:
        name = self.state.current_room
        lines = [self.rooms[name].description]
        if name in ITEMS:
            lines.append(f"Items here: {ITEMS[name]}")
        if name == "intro":
            lines.append("Doors lead to: " + ", ".join(EXITS["intro"]))
        return "\n".join(lines)

    def _solve_current(self) -> None:
        room = self.rooms[self.state.current_room]
        try:
            output = room.solve(self.state)
        except NotImplementedError:
            self.transcript.say("[Game] This room is not built yet.")
            return
        except (OSError, ValueError, RuntimeError) as exc:
            self.transcript.say(f"[Game] Could not analyse this room: {exc}")
            return
        self.state.inventory.update(self.state.tokens)
        for line in output:
            self.transcript.say(line)

    def _require_arg(self, arg: str, usage: str) -> bool:
        if not arg:
            self.transcript.say(f"Usage: {usage}")
            return False
        return True

    def cmd_look(self, _arg: str) -> None:
        self.transcript.say(self._describe())

    def cmd_move(self, arg: str) -> None:
        if not self._require_arg(arg, "move <room>"):
            return
        target = arg.lower()
        if target not in self.rooms:
            self.transcript.say(f"There is no room called '{target}'.")
            return
        if target == self.state.current_room:
            self.transcript.say(f"You are already in {target}.")
            return
        self.state.current_room = target
        self.transcript.say(self._describe())

    def cmd_inspect(self, arg: str) -> None:
        if not self._require_arg(arg, "inspect <item>"):
            return
        if ITEMS.get(self.state.current_room) != arg:
            self.transcript.say(f"There is no '{arg}' here.")
            return
        self._solve_current()

    def cmd_use(self, arg: str) -> None:
        if not self._require_arg(arg, "use <item>"):
            return
        if ITEMS.get(self.state.current_room) == arg:
            self._solve_current()
        elif arg in self.state.inventory:
            self.transcript.say(f"Nothing happens when you use {arg}.")
        else:
            self.transcript.say(f"You don't have '{arg}'.")

    def cmd_inventory(self, _arg: str) -> None:
        if not self.state.inventory:
            self.transcript.say("You are carrying nothing.")
        else:
            self.transcript.say("You currently hold: " + ", ".join(sorted(self.state.inventory)))

    def cmd_hint(self, _arg: str) -> None:
        self.transcript.say("No hints yet. Look around and inspect everything.")

    def cmd_save(self, arg: str) -> None:
        if not self._require_arg(arg, "save <file>"):
            return
        data = {
            "current_room": self.state.current_room,
            "inventory": sorted(self.state.inventory), 
            "tokens": self.state.tokens,
        }
        try:
            Path(arg).write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as exc:
            self.transcript.say(f"Could not save to '{arg}': {exc}")
            return
        self.transcript.say("[Game] Progress saved.")

    def cmd_load(self, arg: str) -> None:
        if not self._require_arg(arg, "load <file>"):
            return
        path = Path(arg)
        if not path.exists():
            self.transcript.say(f"No save file named '{arg}'.")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            state = GameState(
                current_room=data["current_room"],
                inventory=set(data["inventory"]),
                tokens=dict(data["tokens"]),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.transcript.say(f"Could not load '{arg}': save file is malformed ({exc}).")
            return
        if state.current_room not in self.rooms:
            self.transcript.say(f"Could not load '{arg}': unknown room '{state.current_room}'.")
            return
        self.state = state  
        self.transcript.say("[Game] Progress loaded.")
        self.transcript.say(self._describe())

    def cmd_help(self, _arg: str) -> None:
        self.transcript.say(
            "Commands: look, move <room>, inspect <item>, use <item>, "
            "inventory, hint, save <file>, load <file>, help, quit"
        )

    def cmd_quit(self, _arg: str) -> bool:
        self.transcript.say(f"[Game] Goodbye. Transcript written to {self.transcript.path}")
        return False