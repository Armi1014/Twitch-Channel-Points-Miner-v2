# Twitch Channel Points Miner (Armi1014 Fork)

Stability-focused fork of `Twitch-Channel-Points-Miner-v2` with stronger streak reliability, cleaner priority behavior, and less transient log noise.

## Quick Start (60 Seconds)

1. Clone and enter the repo:

```sh
git clone https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2
cd Twitch-Channel-Points-Miner-v2
```

2. Create a virtual environment and install dependencies:

```sh
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. Create your runner and start:

```sh
cp example.py run.py  # Windows: copy example.py run.py
python run.py
```

## Why This Fork (vs Upstream)

- More resilient under transient Twitch/API/network issues (retry/backoff hardening).
- More reliable watch streak handling, including already-online channels at startup.
- Per-account streak cache (`watch_streak_cache.<account>.json`) to avoid multi-account clashes.
- Clear favorite priority flow with `Priority.FAVORITE` + `favorite=True`.
- Reduced log spam for recurring transient timeout patterns.

### Startup Performance (Sample)

- Upstream sample startup: `2m 59s` (`179s`)
- This fork sample startup: `14s`
- Improvement: `165s` faster (`92.2%` less startup time, `~12.8x` speedup)

Sample results vary by account size, network quality, and Twitch backend health.

## Priority, Favorites, and Streak Setup

- Twitch awards points on up to 2 streams at once.
- With `Priority.STREAK` first, the miner tries eligible streak channels first.
- If no streak is currently eligible, it falls back to your next priorities.
- `Priority.FAVORITE` applies only to streamers with `favorite=True`.
- `watch_streak=True` must be set inside `StreamerSettings(...)`, not directly on `Streamer(...)`.

```python
from TwitchChannelPointsMiner import TwitchChannelPointsMiner
from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer, StreamerSettings

twitch_miner = TwitchChannelPointsMiner(
    username="your-twitch-username",
    priority=[Priority.STREAK, Priority.FAVORITE, Priority.ORDER],
    watch_streak_min_offline_seconds=1800,  # 1800 = 30 min default, 0 = aggressive
)

twitch_miner.mine(
    [
        Streamer("favorite_channel", settings=StreamerSettings(favorite=True, watch_streak=True)),
        Streamer("streak_channel", settings=StreamerSettings(watch_streak=True)),
        Streamer("normal_channel"),
    ]
)
```

## FAQ

### Where do I set favorites?

Inside `StreamerSettings`, for example: `Streamer("name", settings=StreamerSettings(favorite=True))`.

### Where do I set streak wait time?

In `TwitchChannelPointsMiner(...)` with `watch_streak_min_offline_seconds` (`1800` default, `0` for no offline wait).

### What happens to streamers already online at startup?

They are still checked; the miner can probe streak status for already-online channels.

### Why is someone missing in `watch_streak_cache.<account>.json`?

That file stores streak sessions, not a full streamer list, so entries appear when a streak session is created or updated.

### Why do I still see occasional `503` or `service timeout`?

Those are usually Twitch-side backend issues; the miner retries and suppresses common spam, but cannot eliminate all upstream outages.

## Links

- Releases: https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2/releases
- Full example config: [example.py](example.py)
- Fork details: [FORK_FEATURES.md](FORK_FEATURES.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Twitch docs: https://help.twitch.tv/s/article/channel-points-guide

## Disclaimer

Use at your own risk. This project is not affiliated with Twitch.
