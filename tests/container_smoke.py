"""Credential-free runner for checking the documented Compose mounts in CI."""

from importlib.metadata import version
import json
from pathlib import Path

from TwitchChannelPointsMiner import __version__

assert version("Twitch-Channel-Points-Miner-v2") == __version__
assert Path("assets").is_dir(), "Container is missing analytics assets"
try:
    with Path(__file__).open("a"):
        pass
except OSError:
    pass
else:
    raise AssertionError("run.py mount must be read-only")

cookie = Path("cookies/container-smoke.json")
if cookie.exists():
    assert json.loads(cookie.read_text()) == {"test": "persisted"}
else:
    cookie.write_text(json.dumps({"test": "persisted"}))

state = Path("logs/.state/container-smoke.json")
state.parent.mkdir(parents=True, exist_ok=True)
count = json.loads(state.read_text())["runs"] if state.exists() else 0
state.write_text(json.dumps({"runs": count + 1}))
with Path("logs/container-smoke.log").open("a") as log:
    log.write("container started\n")
print(f"Container imports and mounts OK; persisted run count: {count + 1}")
