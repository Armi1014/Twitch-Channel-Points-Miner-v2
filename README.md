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

## Notifications

All six providers have commented-out examples inside `LOGGER_SETTINGS` in
[example.py](example.py). Copy the file to `run.py`, uncomment the provider's
import and its configuration block, and replace the placeholders. Do this
before creating `TwitchChannelPointsMiner`; changing `LOGGER_SETTINGS` afterwards
does not reconfigure an existing miner. Several providers can be enabled together.

`NOTIFICATION_EVENTS` controls which messages are sent. The example selects
streamer-online, your-account subscription, and drop-claim events. Remove entries
or add others such as `Events.STREAMER_OFFLINE`, `Events.BET_WIN`, and
`Events.CHAT_MENTION`. A provider can use its own `events=[...]` list instead.
An empty list sends no events. Notifications remain disabled until you uncomment
a provider block.

| Provider | Required configuration and setup |
|---|---|
| Telegram | Create a bot with [BotFather](https://core.telegram.org/bots/tutorial#obtain-your-bot-token), copy its token into `token`, and send `/start` to your bot. Use your destination's numeric `chat_id`; after sending a message, the Bot API's [`getUpdates`](https://core.telegram.org/bots/api#getupdates) response exposes it in `message.chat.id`. Group IDs may be negative; the bot must be a member with permission to send messages. `disable_notification=True` sends silently. |
| Discord | In **Server Settings → Integrations → Webhooks**, create a webhook for the destination channel and copy its full URL into `webhook_api`. See [Discord's guide](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks). |
| Gotify | Create an **application** in your Gotify server and use its application token in `endpoint="https://YOUR_HOST/message?token=YOUR_TOKEN"`. `priority=5` sets the message priority. See [Gotify's guide](https://gotify.net/docs/pushmsg). |
| Matrix | Set `username`, `password`, the `homeserver` hostname without `https://`, and the destination's internal `room_id` such as `!abc:example.org`, available in your client's room information. The account must already be joined to the room and support [password login](https://spec.matrix.org/latest/client-server-api/#password-based). This helper sends plain room messages and does not implement encrypted-room messaging. It attempts login as soon as its configuration is constructed. |
| Pushover | Copy your account's user key into `userkey`; create an application and put its API token in `token`. The example uses normal `priority=0` and `sound="pushover"`. Emergency priority requires fields this helper does not expose. See [Pushover's API guide](https://pushover.net/api). |
| Generic webhook | Set `endpoint` and `method="GET"` or `"POST"`. The receiver must accept `event_name` and `message` as URL query parameters; this helper does not send JSON. Use the dedicated Discord helper for Discord webhooks. |

Keep real tokens, webhook URLs, passwords, and your configured `run.py` private.
Restart the miner after changing its configuration. If a notification does not
arrive, check the selected event, credentials, destination permissions, and miner
logs. Matrix startup also reports unsuccessful login. Subscription notices are
about your own Twitch account; see [Subscription Notifications](#subscription-notifications)
for the IRC and websocket paths.

## Docker And Docker Compose

Use Docker with the Compose v2 plugin. Run these commands from this repository
on the Docker host; Python does not need to be installed on that host.

```sh
cp example.py run.py
mkdir -p cookies logs
```

Edit `run.py`: set your Twitch username and channels or enable followed channels.
Leave optional notification blocks disabled until configured. Existing sessions
can be reused by copying `cookies/YOUR_USERNAME.pkl` into the new `cookies/`
directory. It must match the username in `run.py`.

Build the image from this fork's source, validate the Compose configuration,
then start in the foreground so you can see the first-login activation code:

```sh
docker build -t twitch-channel-points-miner:local .
docker compose config --quiet
docker compose up
```

If there is no saved session, follow the activation instructions printed by the
miner. After login, cookies are saved in the mounted directory. Press Ctrl+C to
stop this foreground run, then start it in the background:

```sh
docker compose up -d
docker compose logs --tail 100 -f miner
```

On Windows PowerShell, use `Copy-Item example.py run.py` and
`New-Item -ItemType Directory -Force cookies, logs` for the preparation commands;
the Docker commands are the same.

The supplied [docker-compose.yml](docker-compose.yml) uses an image built in
advance, which also supports Portainer deployments. Its persistent paths are:

| Host path | Container path | Access |
|---|---|---|
| `run.py` | `/usr/src/app/run.py` | Read-only configuration |
| `cookies/` | `/usr/src/app/cookies/` | Read/write saved login |
| `logs/` | `/usr/src/app/logs/` | Read/write logs, reports, and `logs/.state/` |

By default the host paths are beside the Compose file. Set `MINER_DATA_DIR` to
an existing data directory to use another location, or `MINER_IMAGE` to change
the image tag. Create `run.py`, `cookies/`, and `logs/` before starting; the mounts
deliberately fail on missing paths rather than turning a missing `run.py` into
a directory. The data directories must be writable by the container. Cookies
and logs are not baked into the image. Analytics is disabled in the example and
no inbound port is required for ordinary mining.

To stop or remove the container:

```sh
docker compose stop
docker compose down
```

Both commands preserve the host's cookies and logs. After updating the source,
rebuild and recreate the container without removing those directories:

```sh
docker build -t twitch-channel-points-miner:local .
docker compose up -d --force-recreate
```

For a direct Docker run on Linux/macOS, using the same prepared files:

```sh
docker run --rm -it --init --stop-timeout 120 \
  --mount "type=bind,source=$PWD/run.py,target=/usr/src/app/run.py,readonly" \
  --mount "type=bind,source=$PWD/cookies,target=/usr/src/app/cookies" \
  --mount "type=bind,source=$PWD/logs,target=/usr/src/app/logs" \
  twitch-channel-points-miner:local
```

## Portainer

Use a **Docker Standalone** environment. Build the image on the Docker host
selected in Portainer using the command above, and prepare a data directory
there, for example `/opt/twitch-miner`, containing configured `run.py`, `cookies/`,
and `logs/`. Paths refer to that Docker host, even when Portainer runs elsewhere
or you access it from your own PC. See [Docker's bind-mount documentation](https://docs.docker.com/engine/storage/bind-mounts/).

1. Open **Stacks → Add stack** and name it `twitch-miner`.
2. Paste the contents of [docker-compose.yml](docker-compose.yml) into the editor.
3. Add `MINER_DATA_DIR=/opt/twitch-miner` under the stack's environment variables.
   Keep the image's default tag, or set `MINER_IMAGE` to the tag built on that host.
4. Deploy the stack and open the miner container's **Logs** to complete Twitch
   activation if needed. Portainer's **Console** is available for troubleshooting;
   no interactive console is required for device-code activation.
5. After rebuilding an updated image on that host, recreate the stack's container
   with the same environment values and mounts. Use the local image instead of
   requesting a registry pull for the `:local` tag.

The Compose file has no `build` directive because Portainer's remote-environment
stack deployment does not support those steps. See [Portainer's known issue](https://docs.portainer.io/faqs/known-issues/docker-compose-files-including-build-steps-fail).
The same image and Compose configuration can be checked first with the CLI
before deploying through Portainer.

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
- `WATCH_STREAK` is treated as a hint that Twitch may have awarded the streak.
- The miner marks a streak completed only after Twitch's streak day count increases.

This matters because Twitch can send misleading streak signals. The miner keeps retrying pending streaks through the current broadcast instead of stopping on a false alarm.

More streak details are in [FAQ.md](FAQ.md).

## Drops

Drops depend on two things:

- Twitch accepting playback/watch activity for the stream.
- Twitch GQL queries returning current inventory, campaign, and claim data.

This fork keeps drops claiming running when `claim_drops=True`, treats common Twitch campaign discovery failures as non-fatal, and uses fallback campaign matching when highlighted campaign IDs are missing.

The current drops-related Twitch GQL hashes are checked against live Twitch behavior and compared with [mpforce's working implementation](https://github.com/mpforce1/Twitch-Channel-Points-Miner). Twitch can still return transient `service timeout` or backend errors; those are Twitch-side and the miner should continue running.

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
