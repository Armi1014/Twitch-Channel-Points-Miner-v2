# Twitch Channel Points Miner (Armi1014 Fork)

A reliability-first fork of `Twitch-Channel-Points-Miner-v2` focused on practical day-to-day use: faster startup, clearer priority behavior, stronger watch streak handling, drops resilience, reports, and cleaner subscription notifications.

This project is not affiliated with Twitch. Use it at your own risk and make sure you understand the platform rules before using automation tools.

## Requirements

- Python `>=3.10`
- Git
- `uv` recommended for setup
- `pip`/venv fallback supported through `requirements.txt`

## Quick Start

```sh
git clone https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2
cd Twitch-Channel-Points-Miner-v2
cp example.py run.py
uv sync
uv run run.py
```

Edit `run.py` before the first real run. Most users only need to set `USERNAME`, `PASSWORD`, and `STREAMERS`.

Hermes is the default websocket backend. To force the legacy PubSub transport, set `USE_HERMES = False` in `run.py`.

## Pip Fallback

```sh
python -m venv .venv
source .venv/bin/activate
cp example.py run.py
pip install -r requirements.txt
python run.py
```

On Windows, activate the venv with `.venv\Scripts\activate`.

## First Config Checklist

- Set your Twitch account in `USERNAME`.
- Use `PASSWORD = None` if you want the miner to ask at startup instead of storing the password in `run.py`.
- Add channels to `STREAMERS`.
- Mark important channels with `StreamerSettings(favorite=True)` if `Priority.FAVORITE` is in your priority order.
- Drops are enabled by default through `claim_drops=True`.
- Daily reports are enabled by default; weekly, monthly, and yearly reports can be enabled separately.
- Keep `USE_HERMES = True` unless you need to troubleshoot with the legacy PubSub transport.

See [example.py](example.py) for a complete starter config.

## What This Fork Improves

- Faster startup on medium and large channel lists.
- More resilient Twitch API, GQL, and websocket handling.
- Better watch streak behavior for already-online channels and delayed Twitch signals.
- Predictable favorite priority behavior.
- Drops inventory claiming and campaign matching that keep working through flaky Twitch campaign discovery.
- Cleaner Excel reports with daily, weekly, monthly, and yearly folders.
- Hidden local state files under `logs/.state/` so the root `logs/` folder stays cleaner.
- Self-only subscription notifications for Discord and other webhook-style integrations.

For implementation history and deeper notes, see [FORK_FEATURES.md](FORK_FEATURES.md).

## Watch Streaks

The miner now treats Twitch watch streaks conservatively:

- `WATCH` means normal watch points were awarded.
- `WATCH_STREAK` means the streak reward was confirmed.
- Normal `WATCH` rewards no longer mark the streak as completed.

This matters because Twitch can award normal watch points before it sends the streak reward. The miner keeps waiting for real streak proof instead of stopping too early.

More streak details are in [FAQ.md](FAQ.md).

## Drops

Drops depend on two things:

- Twitch accepting playback/watch activity for the stream.
- Twitch GQL queries returning current inventory, campaign, and claim data.

This fork keeps drops claiming running when `claim_drops=True`, treats common Twitch campaign discovery failures as non-fatal, and uses fallback campaign matching when highlighted campaign IDs are missing.

The current drops-related Twitch GQL hashes are synced from [mpforce's working implementation](https://github.com/mpforce1/Twitch-Channel-Points-Miner). Twitch can still return transient `service timeout` or backend errors; those are Twitch-side and the miner should continue running.

## Subscription Notifications

This fork can send `Events.SUBSCRIPTION` notifications to Discord or other webhook-style integrations.

It listens for:

- Twitch IRC `USERNOTICE` events.
- Twitch websocket gift-sub signals that can arrive even when the account is not present in chat.

It alerts only for subscription events about your own account:

- you subscribe
- you renew a subscription
- you receive a sub gift
- you upgrade a gift or Prime subscription

It ignores subscription events for other viewers.

Notes:

- IRC subscription notices still require chat to be enabled for that streamer.
- `chat=ChatPresence.NEVER` disables only the IRC subscription path for that channel.
- Websocket gift-sub notices use the same `Events.SUBSCRIPTION` message format and are locally deduped.

## Reports And State Files

Reports are written under `logs/reports/` by period:

- `logs/reports/daily/`
- `logs/reports/weekly/`
- `logs/reports/monthly/`
- `logs/reports/yearly/`

Daily reports keep all point columns. Weekly, monthly, and yearly reports show only the point columns relevant to that period.

Local state files are kept in `logs/.state/`, including:

- watch streak cache
- daily points baselines
- subscription notification dedupe data

On first startup after updating, legacy state files from `logs/` are copied into `logs/.state/` automatically. The old files are left in place as backups.

Do not delete files inside `logs/.state/` unless you intentionally want to reset local report and watch streak history.

## Troubleshooting

- For setup and config questions, see [FAQ.md](FAQ.md).
- For feature details and reliability notes, see [FORK_FEATURES.md](FORK_FEATURES.md).
- For a complete runnable config, see [example.py](example.py).
- For contribution notes, see [CONTRIBUTING.md](CONTRIBUTING.md).

Common runtime notes:

- Occasional `503`, `service timeout`, or Twitch backend errors can happen and are usually transient.
- For debug logs, set `LoggerSettings` to `logging.DEBUG` and inspect the newest file under `logs/`.
- If drops stop progressing, first check whether Twitch is accepting playback and whether recent GQL hashes are still valid.

## Links

- [Latest Releases](https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2/releases)
- [Example Config](example.py)
- [FAQ](FAQ.md)
- [Fork Features](FORK_FEATURES.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
