# Twitch Channel Points Miner (Armi1014 Fork)

Stability-focused fork of `Twitch-Channel-Points-Miner-v2` with better streak handling, cleaner priority behavior, and less transient log spam.

## Start in 60 Seconds

```sh
git clone https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2
cd Twitch-Channel-Points-Miner-v2
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp example.py run.py  # Windows: copy example.py run.py
python run.py
```

## Why This Fork

- Better runtime resilience when Twitch APIs are unstable.
- Per-account streak cache file (`watch_streak_cache.<account>.json`) to avoid cross-account clashes.
- Clear `Priority.FAVORITE` support (`favorite=True` in streamer settings).
- Safer startup behavior for missing streak checks.

## What Changed vs Upstream

- Better retry/backoff handling for transient network and DNS/connection issues.
- Better watch streak reliability and per-account streak cache handling.
- Better startup behavior when channels are already online.
- Better priority handling with explicit `Priority.FAVORITE` + `favorite=True`.
- Less noisy logs for known transient Twitch timeout patterns.

## Quick Start

1. Clone:

```sh
git clone https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2
cd Twitch-Channel-Points-Miner-v2
```

2. Install:

```sh
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
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
    watch_streak_min_offline_seconds=1800,  # 1800 = 30 min, 0 = no wait
)

twitch_miner.mine(
    [
        Streamer("favorite_channel", settings=StreamerSettings(favorite=True, watch_streak=True)),
        Streamer("streak_channel", settings=StreamerSettings(watch_streak=True)),
        Streamer("normal_channel"),
    ]
)
```

4. Run:

```sh
python run.py
```

## Priority and Streak Behavior

- Twitch only gives points on up to 2 streams at once.
- If `Priority.STREAK` is first, miner tries eligible streak channels first.
- If no streak is currently eligible, it falls back to your next priorities.
- `Priority.FAVORITE` works only for streamers created with `Streamer(..., settings=StreamerSettings(favorite=True))`.

## Favorites + Streak Cheat Sheet

- Favorite only:
  - `Streamer("name", settings=StreamerSettings(favorite=True))`
- Streak only:
  - `Streamer("name", settings=StreamerSettings(watch_streak=True))`
- Favorite + streak:
  - `Streamer("name", settings=StreamerSettings(favorite=True, watch_streak=True))`
- Recommended priority:
  - `priority=[Priority.STREAK, Priority.FAVORITE, Priority.ORDER]`
- Common mistake:
  - `watch_streak=True` must be inside `StreamerSettings(...)`, not directly on `Streamer(...)`.

## FAQ

### Where do I set favorites?

Inside `StreamerSettings`, for example:

```python
Streamer("name", settings=StreamerSettings(favorite=True))
```

### Where do I set streak wait time?

In `TwitchChannelPointsMiner(...)`:

```python
watch_streak_min_offline_seconds=1800
```

- `1800` = 30 minutes (default)
- `0` = no offline wait (more aggressive streak checking)

### What happens to streamers already online at startup?

They are not ignored. The miner can still probe streak status for already-online channels.

### Why is someone missing in `watch_streak_cache.<account>.json`?

That file stores streak sessions, not a full streamer list. A streamer appears there when a streak session is created/updated.

### Why do I still see occasional `503` / `service timeout`?

Those usually come from Twitch backend instability. The miner retries and suppresses common timeout spam, but cannot fully control Twitch-side outages.

## Links

- Releases: https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2/releases
- Full example config: [example.py](example.py)
- Fork details: [FORK_FEATURES.md](FORK_FEATURES.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Twitch docs: https://help.twitch.tv/s/article/channel-points-guide

## Disclaimer

Use at your own risk. This project is not affiliated with Twitch.
