import re

TAG_RE = re.compile(r"^[A-Z_]+(\[[A-Z0-9]+\])?(\.[A-Z0-9_]+)?=")


class Transcript:

    def __init__(self, path: str):
        self.path = path
        self.lines: list[str] = []   
        self.tags: dict[str, str] = {}  

    def echo(self, command: str) -> None:
        self.lines.append(f"> {command}")

    def say(self, text: str) -> None:
        print(text)
        for line in text.splitlines():
            match = TAG_RE.match(line)
            if match:
                key = line[:match.end() - 1]
                self.tags[key] = line[match.end():]
            else:
                self.lines.append(line)

    def write(self) -> None:
        
        with open(self.path, "w", encoding="utf-8", newline="\n") as f:
            for line in self.lines:
                f.write(line + "\n")
            if self.tags:
                f.write("\n")
            for key, value in self.tags.items():
                f.write(f"{key}={value}\n")