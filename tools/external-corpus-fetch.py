#!/usr/bin/env python3
"""external-corpus-fetch — unified dispatcher for corpus ingesters.

Lane 9 of MCP harness review (PR #658) commit 7. Designed by sub-agent
ac97d731deebed811.

Routes to the 4 existing per-source ingesters instead of parallel-building.
This tool is ROUTING ONLY — does not invent new ingestion functionality.

Existing ingesters dispatched:
- zkbugs:  tools/zkbugs-ingest.py     (zksecurity/zkbugs corpus)
- solodit: tools/solodit-ingest.py    (Solodit findings via MCP)
- contest: tools/contest-ingest.py    (Code4rena / Sherlock / etc. caches)
- rust:    tools/rust-corpus-ingest.py (offline Rust corpus mining)

Usage:
    tools/external-corpus-fetch.py --kind=zkbugs --slug=zkbugs-bootstrap
    tools/external-corpus-fetch.py --kind=solodit -- --from-json /tmp/findings.json
    tools/external-corpus-fetch.py --kind=rust --refresh -- --corpus-root /path/to/rust
    tools/external-corpus-fetch.py --kind=zkbugs -- --zkbugs-root /tmp/zkbugs

The `--` separator passes remaining args verbatim to the underlying
ingester (e.g. --zkbugs-root, --from-json, --corpus-root).
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent

DISPATCH = {
    "zkbugs":  ["python3", str(ROOT / "zkbugs-ingest.py")],
    "solodit": ["python3", str(ROOT / "solodit-ingest.py")],
    "contest": ["python3", str(ROOT / "contest-ingest.py")],
    "rust":    ["python3", str(ROOT / "rust-corpus-ingest.py")],
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--kind", required=True, choices=list(DISPATCH))
    parser.add_argument("--slug", default=None, help="optional slug passthrough")
    parser.add_argument("--url", default=None, help="reserved for future live-fetch lane")
    parser.add_argument("--refresh", action="store_true", help="passes --force-refresh")
    parser.add_argument("--language", default=None,
                        help="optional language filter (rust/go/sol/etc.) — passed to solodit/zkbugs")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="args after `--` are passed verbatim to the ingester")
    args = parser.parse_args(argv)

    cmd = DISPATCH[args.kind][:]
    # Forward args that the ingester is likely to support
    if args.slug:
        cmd += ["--slug", args.slug]
    if args.refresh:
        cmd += ["--force-refresh"]
    if args.language:
        cmd += ["--language", args.language]
    if args.dry_run:
        cmd += ["--dry-run"]

    # Strip leading `--` separator from extras
    extras = list(args.extra or [])
    if extras and extras[0] == "--":
        extras = extras[1:]
    cmd += extras

    sys.stderr.write(f"[external-corpus-fetch] dispatching: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
