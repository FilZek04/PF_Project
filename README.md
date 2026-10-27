# Cyber Escape Room (group04)

A command-line escape room for the Programming Fundamentals shared task. You play a
blue-team defender who moves through four analysis rooms, works through the evidence
in `data/`, collects four tokens (KEYPAD, DNS, SAFE, PID) and signs them at the Final Gate.

## Requirements

- Python 3.11 or newer (the project is developed on 3.13; see `environment.yml`)
- Standard library only, so there is nothing to `pip install`

Optional conda environment:

```bash
conda env create -f environment.yml
conda activate pf-project
```

## How to run

From the project root:

```bash
python escape.py --start intro --data data --transcript run.txt
```

| Option | Default | Meaning |
|---|---|---|
| `--start` | `intro` | Room to start in (`intro`, `soc`, `dns`, `vault`, `malware`, `final`) |
| `--data` | `data` | Folder that holds the data pack |
| `--transcript` | `run.txt` | File the transcript is written to when the game ends |

### Commands

| Command | What it does |
|---|---|
| `look` | Describe the current room and its items |
| `move <room>` | Go to another room (`intro`, `soc`, `dns`, `vault`, `malware`, `final`) |
| `inspect <item>` | Analyse the item in the current room and collect its token |
| `use <item>` | Use an item; `use gate` at the Final Gate computes the HMAC |
| `inventory` | Show the tokens you hold |
| `hint` | Show a hint |
| `save <file>` / `load <file>` | Save or restore progress as JSON |
| `help` | List the commands |
| `quit` | Leave the game and write the transcript |

### Full run

```text
move soc
inspect auth.log
move dns
inspect dns.cfg
move vault
inspect vault_dump.txt
move malware
inspect proc_tree.jsonl
move final
use gate
quit
```

You can also pipe the commands in for a non-interactive run:

```bash
python escape.py --transcript run.txt < commands.txt
```

## Rooms

| Room | Item | Token | Technique |
|---|---|---|---|
| SOC Triage Desk | `auth.log` | KEYPAD | Validate SSH log lines and find the /24 with the most failed logins |
| DNS Closet | `dns.cfg` | DNS | Parse `key=value` lines; decode `token_tag`, then reverse ROT13 → Base64 → UTF-8 |
| Vault Corridor | `vault_dump.txt` | SAFE | Compiled regex for `SAFE{a-b-c}`, keep the one where `a + b == c` |
| Malware Lab | `proc_tree.jsonl` | PID | Build a process graph and find the exfiltration process with BFS and DFS (with a `visited` set) |
| Final Gate | `final_gate.txt` | — | `MSG = group_id\|tokens in token_order`, HMAC-SHA256 with `hmac_key` |

Malformed input lines are skipped and counted; nothing is hardcoded. All values come from the data pack.

## Transcript (`run.txt`)

The game prints everything to the screen and writes `run.txt` when you `quit` (or
press Ctrl-D). Each tagged line (`TOKEN[...]`, `EVIDENCE[...]`, `FINAL_GATE`, `MSG`,
`HMAC`) appears exactly once, with its latest value, at the end of the file.

Produce the submitted `run.txt` in a single session. A loaded save restores your tokens
but not the evidence lines from the earlier session.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover the parsing and analysis functions of every room, the final-gate
message and HMAC, the engine commands and the transcript.

## Project structure

```text
escape.py                 CLI entry point (argparse)
escaperoom/
  engine.py               GameState, REPL and command handlers
  transcript.py           Collects output and writes run.txt
  utils.py                Parsing and analysis helpers for every room
  rooms/
    base.py               Room base class
    soc.py dns.py vault.py malware.py final.py
data/                     group04 data pack
tests/                    unittest test suite
```
