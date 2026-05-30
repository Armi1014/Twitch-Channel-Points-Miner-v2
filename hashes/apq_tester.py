#!/usr/bin/env python3
"""
Test GraphQL persisted query hashes against an endpoint.

By default, runs against Twitch's GQL endpoint using every operation declared
in TwitchChannelPointsMiner.constants.GQLOperations (sending each hash with its
matching operationName and variables).

Each hash gets one of three verdicts:
  WORKS        -> hash IS registered server-side (regardless of auth/variable errors)
  BROKEN       -> hash is unregistered (PersistedQueryNotFound) -- needs updating
  INCONCLUSIVE -> couldn't tell (network error, non-200 HTTP, server doesn't support APQ)

Internally each response is also tagged with a finer category for debugging:
  ok / partial / error -> WORKS  (hash registered; query may still fail downstream)
  not_found            -> BROKEN
  not_supported / http_<code> / exception -> INCONCLUSIVE

When BROKEN hashes are detected, this script only prints the actionable list:
operation name + current hash. It does not discover replacements. Get the new
hash manually from Twitch DevTools: F12 -> Network -> filter "gql" -> trigger
the feature -> copy extensions.persistedQuery.sha256Hash.

Usage:
  pip install aiohttp
  python tests/apq_tester.py                                  # constants.py + Twitch URL
  python tests/apq_tester.py -H "Authorization: OAuth XYZ"    # add auth for fuller responses
  python tests/apq_tester.py --hashes hashes.txt              # legacy: flat hash list
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import aiohttp

# tests/ lives next to the package; make the project root importable when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from TwitchChannelPointsMiner.constants import CLIENT_ID, GQLOperations  # noqa: E402


def apq_payload(sha256_hash: str,
                variables: Optional[dict] = None,
                operation_name: Optional[str] = None) -> dict:
    """Build an Apollo Persisted Query request body."""
    payload = {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": sha256_hash,
            }
        }
    }
    if variables is not None:
        payload["variables"] = variables
    if operation_name:
        payload["operationName"] = operation_name
    return payload


def operations_from_constants() -> list:
    """Extract [{name, hash, variables}, ...] from GQLOperations."""
    ops = []
    for attr_name, value in vars(GQLOperations).items():
        if attr_name.startswith("_"):
            continue
        # PersonalSections is wrapped in a single-element tuple
        if isinstance(value, tuple) and value:
            value = value[0]
        if not isinstance(value, dict):
            continue
        sha = ((value.get("extensions") or {}).get("persistedQuery") or {}).get("sha256Hash")
        if not sha:
            continue
        ops.append({
            "name": value.get("operationName") or attr_name,
            "hash": sha,
            "variables": value.get("variables"),
        })
    return ops


def operations_from_file(path: str) -> list:
    """Read hashes from a text file (one per line, # comments allowed)."""
    out = []
    for line in Path(path).read_text().splitlines():
        h = line.strip()
        if not h or h.startswith("#"):
            continue
        out.append({"name": h[:12], "hash": h, "variables": None})
    return out


def classify(status: int, body: dict) -> str:
    errors = body.get("errors") or []
    codes = []
    for e in errors:
        ext = e.get("extensions") or {}
        codes.append(str(ext.get("code") or e.get("message", "")))

    if any("PersistedQueryNotFound" in c for c in codes):
        return "not_found"
    if any("PersistedQueryNotSupported" in c for c in codes):
        return "not_supported"
    if status == 200 and not errors and body.get("data"):
        return "ok"
    if status == 200 and errors and body.get("data") is not None:
        return "partial"
    if errors:
        return "error"
    return f"http_{status}"


VERDICT_OF = {
    "ok": "WORKS",
    "partial": "WORKS",
    "error": "WORKS",
    "not_found": "BROKEN",
}


def verdict_of(category: str) -> str:
    return VERDICT_OF.get(category, "INCONCLUSIVE")


_USE_COLOR = sys.stderr.isatty()
_COLORS = {
    "WORKS": "\033[32m",        # green
    "BROKEN": "\033[31m",       # red
    "INCONCLUSIVE": "\033[33m",  # yellow
}
_RESET = "\033[0m"
_GLYPH = {"WORKS": "[OK]", "BROKEN": "[!!]", "INCONCLUSIVE": "[??]"}


def paint(verdict: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(verdict, '')}{text}{_RESET}"


async def test_op(session, url, op, method, cli_variables,
                  cli_operation_name, semaphore) -> dict:
    variables = cli_variables if cli_variables is not None else op.get("variables")
    operation_name = cli_operation_name or op.get("name")
    payload = apq_payload(op["hash"], variables, operation_name)
    async with semaphore:
        try:
            if method == "GET":
                params = {"extensions": json.dumps(payload["extensions"])}
                if variables is not None:
                    params["variables"] = json.dumps(variables)
                if operation_name:
                    params["operationName"] = operation_name
                async with session.get(url, params=params) as resp:
                    text, status = await resp.text(), resp.status
            else:
                async with session.post(url, json=payload) as resp:
                    text, status = await resp.text(), resp.status
        except Exception as e:
            return {"name": operation_name, "hash": op["hash"],
                    "category": "exception", "verdict": "INCONCLUSIVE",
                    "error": str(e)}

    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = {"raw": text[:500]}

    category = classify(status, body if isinstance(body, dict) else {})
    return {
        "name": operation_name,
        "hash": op["hash"],
        "status": status,
        "category": category,
        "verdict": verdict_of(category),
        "response": body,
    }


async def run(args):
    if args.hashes:
        ops = operations_from_file(args.hashes)
        print(f"Loaded {len(ops)} hashes from {args.hashes}", file=sys.stderr)
    else:
        ops = operations_from_constants()
        print(f"Loaded {len(ops)} operations from GQLOperations", file=sys.stderr)

    url = args.url or GQLOperations.url

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    for h in (args.header or []):
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    # Twitch GQL rejects requests without a Client-ID; default to the miner's one.
    if not any(k.lower() == "client-id" for k in headers):
        headers["Client-ID"] = CLIENT_ID

    cli_variables = json.loads(Path(args.variables).read_text()) if args.variables else None

    sem = asyncio.Semaphore(args.concurrency)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=not args.insecure)

    results = []
    async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
        tasks = [
            test_op(session, url, op, args.method, cli_variables,
                    args.operation_name, sem)
            for op in ops
        ]
        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            r = await coro
            results.append(r)
            label = r.get("name") or r["hash"][:12]
            v = r["verdict"]
            stamp = paint(v, f"{_GLYPH[v]} {v:12s}")
            print(f"[{i}/{len(ops)}] {stamp} {label:40s} ({r['category']})",
                  file=sys.stderr)
            if v == "WORKS" and r["category"] in ("ok", "partial") and not args.quiet:
                data = (r.get("response") or {}).get("data")
                if data:
                    print(f"   data: {json.dumps(data)[:200]}", file=sys.stderr)

    by_verdict = {"WORKS": [], "BROKEN": [], "INCONCLUSIVE": []}
    for r in results:
        by_verdict[r["verdict"]].append(r)

    print("\n=== Summary ===", file=sys.stderr)
    for v in ("WORKS", "BROKEN", "INCONCLUSIVE"):
        bucket = by_verdict[v]
        cats = {}
        for r in bucket:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        breakdown = ", ".join(f"{k}={n}" for k, n in sorted(cats.items(), key=lambda x: -x[1]))
        line = f"  {_GLYPH[v]} {v:12s} {len(bucket):3d}" + (f"  ({breakdown})" if breakdown else "")
        print(paint(v, line), file=sys.stderr)

    if by_verdict["BROKEN"]:
        print(paint("BROKEN", "\n=== BROKEN hashes (unregistered, need updating) ==="), file=sys.stderr)
        for r in by_verdict["BROKEN"]:
            print(paint("BROKEN", f"  {r['name']:40s} {r['hash']}"), file=sys.stderr)
        print(
            "\nThis tester does not discover new hashes. To update one manually: "
            "open Twitch, press F12, use Network, filter 'gql', trigger the feature, "
            "then copy extensions.persistedQuery.sha256Hash for the matching operation.",
            file=sys.stderr,
        )

    if by_verdict["INCONCLUSIVE"]:
        print(paint("INCONCLUSIVE", "\n=== INCONCLUSIVE hashes (couldn't determine) ==="), file=sys.stderr)
        for r in by_verdict["INCONCLUSIVE"]:
            extra = r.get("error") or r.get("category")
            print(paint("INCONCLUSIVE", f"  {r['name']:40s} {extra}"), file=sys.stderr)

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"\nFull results -> {args.output}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", help=f"GraphQL endpoint URL (default: {GQLOperations.url})")
    p.add_argument("--hashes",
                   help="Optional path to file with one sha256 hash per line. "
                        "When omitted, uses operations from TwitchChannelPointsMiner.constants.GQLOperations.")
    p.add_argument("-m", "--method", choices=["GET", "POST"], default="POST")
    p.add_argument("-c", "--concurrency", type=int, default=10)
    p.add_argument("-t", "--timeout", type=float, default=15.0)
    p.add_argument("-H", "--header", action="append",
                   help="Extra header, e.g. -H 'Authorization: OAuth xxx' (repeatable)")
    p.add_argument("-v", "--variables",
                   help="Path to JSON file with variables (overrides per-op variables for every request)")
    p.add_argument("-o", "--output", help="Write full JSON results here")
    p.add_argument("--operation-name", help="Override operationName for every request")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("-q", "--quiet", action="store_true", help="Don't preview hit data")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
