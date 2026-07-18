#!/usr/bin/env python3
"""paste_content_hash.py — L29-Filing Check C paste-content-hash gate.

Standalone helper. Two modes:

    --record <paste>    Compute SHA-256 of <paste>, write <paste>.hash, exit 0.
    --verify <paste>    Read <paste>.hash, compare to current SHA-256 of <paste>;
                        exit 0 on match, exit 1 on mismatch / missing hash.

Codified from FN7 forensic where pre-submit-check passed at HIGH but a
``FN7_CRITICAL_FINAL_PASTE.md`` was generated 34 minutes later (during an
LLM-review-offline window) and submitted at Critical without a re-run. This
gate ties the gated content to its hash so any post-gate edit is detected by
the filing tool.

Hash file format
----------------
First line: hex digest of SHA-256 over paste bytes.
The filing tool MUST call ``--verify`` immediately before submission and
abort if exit code != 0.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def compute_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hash_path_for(paste: Path) -> Path:
    return paste.with_suffix(paste.suffix + ".hash")


def record(paste: Path) -> int:
    if not paste.is_file():
        print(f"paste-content-hash: ERROR paste-ready not found: {paste}", file=sys.stderr)
        return 2
    digest = compute_sha256(paste)
    hp = hash_path_for(paste)
    hp.write_text(digest + "\n", encoding="utf-8")
    print(f"paste-content-hash: RECORDED {digest[:12]}… → {hp.name}")
    return 0


def verify(paste: Path) -> int:
    if not paste.is_file():
        print(f"paste-content-hash: ERROR paste-ready not found: {paste}", file=sys.stderr)
        return 2
    hp = hash_path_for(paste)
    if not hp.is_file():
        print(
            f"paste-content-hash: FAIL no recorded hash at {hp.name}; "
            "run --record (via pre-submit-check.sh) first",
            file=sys.stderr,
        )
        return 1
    recorded = hp.read_text(encoding="utf-8").strip().split()[0] if hp.read_text(
        encoding="utf-8"
    ).strip() else ""
    current = compute_sha256(paste)
    if recorded != current:
        print(
            f"paste-content-hash: FAIL hash mismatch (recorded={recorded[:12]}… "
            f"current={current[:12]}…); paste was edited after pre-submit gate",
            file=sys.stderr,
        )
        return 1
    print(f"paste-content-hash: PASS hash verified ({current[:12]}…)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--record", metavar="PASTE", help="record SHA-256 of paste")
    grp.add_argument("--verify", metavar="PASTE", help="verify recorded SHA-256")
    args = parser.parse_args(argv)

    if args.record:
        return record(Path(args.record).resolve())
    if args.verify:
        return verify(Path(args.verify).resolve())
    return 2


if __name__ == "__main__":
    sys.exit(main())
