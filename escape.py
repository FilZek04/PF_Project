import argparse
from escaperoom.engine import Engine
from escaperoom.transcript import Transcript


def main():
    parser = argparse.ArgumentParser(description="Cyber Escape Room")
    parser.add_argument("--start", default="intro")
    parser.add_argument("--data", default="data")
    parser.add_argument("--transcript", default="run.txt")
    args = parser.parse_args()

    transcript = Transcript(args.transcript)
    engine = Engine(start=args.start, data_dir=args.data, transcript=transcript)
    engine.run()


if __name__ == "__main__":
    main()