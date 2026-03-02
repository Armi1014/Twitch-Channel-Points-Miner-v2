# Twitch Channel Points Miner (Armi1014 Fork)

Reliable fork of Twitch-Channel-Points-Miner-v2 focused on stability, cleaner priority behavior, and lower log noise.

This miner can watch streams for you, claim bonus points, follow raids, and handle watch streak logic with safer retry and cache behavior.

## Contents

- Core Features
- Quick Start
- Priority, Favorites, and Streaks
- Limits
- Common Issues
- Links
- Disclaimer

## Core Features

- Mines channel points on up to 2 streams at a time (Twitch limit).
- Claims bonus rewards automatically.
- Follows raids automatically.
- Supports watch streak handling with per-account cache.
- Supports explicit favorites priority (`Priority.FAVORITE` + `favorite=True`).
- Handles transient network/API failures more safely (retry/backoff).
- Reduces repeated transient error spam in logs.

## Quick Start

1. Clone:
```sh
git clone https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2
cd Twitch-Channel-Points-Miner-v2
```

2. Install:
```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Create `run.py`:
```python
from TwitchChannelPointsMiner import TwitchChannelPointsMiner
from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer, StreamerSettings

twitch_miner = TwitchChannelPointsMiner(
    username="your-twitch-username",
    priority=[Priority.STREAK, Priority.FAVORITE, Priority.ORDER],
)

twitch_miner.mine([
    Streamer("favorite_channel", settings=StreamerSettings(favorite=True, watch_streak=True)),
    Streamer("normal_channel"),
])
```

4. Run:
```sh
python run.py
```

## Priority, Favorites, and Streaks

For favorites to work:

1. Add `Priority.FAVORITE` in `priority=[...]`.
2. Use `Streamer(...)` entries for favorites (not only plain string usernames).
3. Set favorite inside `StreamerSettings(...)`:
   `Streamer("name", settings=StreamerSettings(favorite=True))`

For streak handling:

1. Keep `Priority.STREAK` high in the priority list (usually first).
2. Set `watch_streak=True` in `StreamerSettings(...)` for channels where you want streak attempts.
3. Put `watch_streak=True` inside `StreamerSettings(...)`, not on `Streamer(...)`.

## Limits

- Twitch only awards channel points on up to 2 streams at the same time.
- Twitch API calls can intermittently fail (`503`, `service timeout`), even when miner logic is correct.

## Common Issues

- `service timeout` or `HTTP 503` in logs:
  - Usually Twitch backend instability. Miner should continue and recover.

- "No watch streaks":
  - Verify `Priority.STREAK` is enabled and high enough.
  - Verify `watch_streak=True` for the target streamers.
  - Temporary Twitch streak-state/API failures can delay streak detection.

- `SyntaxError ... perhaps you forgot a comma`:
  - Usually a missing comma in your `mine([...])` streamer list.

## Links

- Releases: https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2/releases
- Advanced config: [example.py](example.py)
- Fork-specific details: [FORK_FEATURES.md](FORK_FEATURES.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Twitch channel points docs: https://help.twitch.tv/s/article/channel-points-guide

## Disclaimer

No warranty. Use at your own risk. This project is not affiliated with Twitch.
