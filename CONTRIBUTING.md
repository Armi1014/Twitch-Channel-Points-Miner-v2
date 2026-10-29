# Contributing

Contributions to the Armi1014 fork of Twitch Channel Points Miner are welcome.
Read the [code of conduct](CODE_OF_CONDUCT.md) before participating.

## Report a problem or suggest a feature

Search this fork's [issues](https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2/issues)
before opening a report. Use the bug report or feature request form and include
the behavior you expected, the behavior you observed, and the steps to reproduce it.
For bugs, include the miner version or commit, Python version, operating system,
and the relevant log excerpt. Remove credentials and private account details.

## Set up a development environment

Fork and clone [this repository](https://github.com/Armi1014/Twitch-Channel-Points-Miner-v2),
then run:

```sh
uv sync --group dev
uv run pre-commit install
```

Copy `example.py` to your private `run.py` only if you need to run the miner.
Follow the [setup instructions](README.md#quick-start) for Twitch activation.

## Keep changes consistent

- Use English for code comments, logs, notifications, documentation, issues, and commits.
- Use **Twitch Channel Points Miner** as the display name and **Armi1014 fork**
  when the fork needs to be identified. Keep the existing package and repository names.
- Use sentence case for headings and messages. Preserve API names such as
  `Events.BET_PLACED`, Twitch, Discord, GraphQL, and WebSocket.
- Keep notification titles and field names consistent with the
  [notification reference](README.md#notifications).
- Follow the existing Black, isort, and Flake8 hooks in `.pre-commit-config.yaml`.
  Keep edits focused; avoid formatting unrelated files.
- Keep dependency declarations in `pyproject.toml` and update `uv.lock` if they change.
  `requirements.txt` remains the supported pip entry point.
- Keep `run.py`, cookies, logs, tokens, and webhook credentials out of Git.

## Verify the change

Run the relevant existing tests. For example, notification changes use:

```sh
uv run python -m unittest discover -s tests -p test_discord_notifications.py
```

Use a targeted check for code changes. For documentation or message wording,
review the diff and check any affected links or examples. New regression tests
should cover behavior rather than repeat the implementation.

## Open a pull request

Target `master` and use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
Describe the problem, the resulting behavior, relevant validation, and any
compatibility changes. Link the issue if one exists. Update documentation when
the documented behavior or setup changes.

Changes merged into `master` trigger the Docker publishing workflow. The image
is published to GitHub Container Registry for `linux/amd64` and `linux/arm64`.
