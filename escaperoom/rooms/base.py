class Room:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def solve(self, state):
        """Return a list of output lines"""
        raise NotImplementedError