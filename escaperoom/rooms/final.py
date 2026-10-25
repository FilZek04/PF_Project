from escaperoom.utils import parseGate, buildMessage, computeHmac
from escaperoom.rooms.base import Room


class FinalRoom(Room):
    def __init__(self, data_dir):
        super().__init__("final", "You stand before the Final Gate. The console asks for proof.")
        self.data_path = f"{data_dir}/final_gate.txt"

    def solve(self, state):
        group_id, order, key = parseGate(self.data_path)
        message = buildMessage(group_id, order, state.tokens)
        collected = ", ".join(f"{name}={state.tokens[name]}" for name in order)
        return [
            f"Collected tokens: {collected}",
            "FINAL_GATE=PENDING",
            f"MSG={message}",
            f"HMAC={computeHmac(key, message)}",
        ]
