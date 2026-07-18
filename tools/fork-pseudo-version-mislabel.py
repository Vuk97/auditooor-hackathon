#!/usr/bin/env python3
"""D5 — Fork pseudo-version mislabel detector.

Detects go.mod replace entries that use Go pseudo-versions of the shape
    vX.Y.Z-0.YYYYMMDDHHMMSS-<12hex>
where the prefix `vX.Y.Z-0` claims lineage from a specific upstream tag
(e.g. v8.5.2-0 → branched from v8.5.x) but the actual git SHA may be from
a different tag (e.g. v8.0.0). The two-stage flow:

  Stage 1 (offline, default):
    Parse go.mod, emit every replace-block entry with a pseudo-version
    shape, classify each `needs_verification=true`.

  Stage 2 (--verify --upstream-clone <path>):
    For each entry, run `git merge-base --is-ancestor <sha> <claimed-tag>`
    and `git describe --contains <sha>` inside the upstream clone, then
    flag entries where the SHA's described lineage doesn't include the
    claimed prefix tag.

CLI:
    python3 tools/fork-pseudo-version-mislabel.py <go.mod> [--verify --upstream-clone <path>]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


SCHEMA = "auditooor.fork_pseudo_version_mislabel.v1"

# Match a go.mod replace line like:
#   github.com/cosmos/ibc-go/v8 => github.com/dydxprotocol/ibc-go/v8 v8.0.0-rc.0.0.20250312180215-8733b3edf43a
# Or:
#   foo => bar v8.5.2-0.20260428182857-8733b3edf43a
REPLACE_RE = re.compile(
    r"^\s*(?P<lhs>[^\s=]+(?:\s+v[\w\.\-+]+)?)\s*=>\s*"
    r"(?P<target>[^\s]+)\s+(?P<version>v[\w\.\-+]+)\s*$"
)

# Pseudo-version shape: vX.Y.Z[-pre]-N.YYYYMMDDHHMMSS-<sha12>
# Most common forms in cosmos-sdk forks:
#   v8.5.2-0.20260428182857-8733b3edf43a
#   v8.0.0-rc.0.0.20250312180215-8733b3edf43a
PSEUDO_RE = re.compile(
    r"^v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<pre>(?:-[A-Za-z0-9]+(?:\.\d+)*)*)"
    r"\.(?P<ts>\d{14})-(?P<sha>[0-9a-f]{12,40})$"
)

REPLACE_BLOCK_OPEN_RE = re.compile(r"^\s*replace\s*\(\s*$")
REPLACE_BLOCK_CLOSE_RE = re.compile(r"^\s*\)\s*$")
SINGLE_REPLACE_RE = re.compile(r"^\s*replace\s+(?P<rest>.+)$")


@dataclass
class Entry:
    line: int
    lhs: str
    target: str
    version: str
    claimed_lineage: Optional[str]   # e.g. "v8.5.x" or "v8.0.0"
    sha: Optional[str]
    pseudo: bool
    needs_verification: bool
    verification: Optional[dict] = None
    flagged: bool = False
    reason: Optional[str] = None


def _strip_comment(line: str) -> str:
    # Remove trailing line comments while leaving // inside strings untouched.
    # go.mod is simple — no quoted // expected.
    idx = line.find("//")
    if idx >= 0:
        return line[:idx]
    return line


def _parse_replace_rhs(rest: str) -> Optional[re.Match]:
    return REPLACE_RE.match(rest)


def parse_go_mod(path: Path) -> List[Entry]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    out: List[Entry] = []
    in_block = False
    for i, raw in enumerate(lines, start=1):
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        if REPLACE_BLOCK_OPEN_RE.match(stripped):
            in_block = True
            continue
        if in_block and REPLACE_BLOCK_CLOSE_RE.match(stripped):
            in_block = False
            continue
        rhs = None
        if in_block:
            rhs = stripped
        else:
            m = SINGLE_REPLACE_RE.match(stripped)
            if m:
                rhs = m.group("rest")
        if not rhs:
            continue
        m2 = _parse_replace_rhs(rhs)
        if not m2:
            continue
        version = m2.group("version")
        pm = PSEUDO_RE.match(version)
        if pm:
            claimed = f"v{pm.group('major')}.{pm.group('minor')}.{pm.group('patch')}"
            entry = Entry(
                line=i,
                lhs=m2.group("lhs").strip(),
                target=m2.group("target").strip(),
                version=version,
                claimed_lineage=claimed,
                sha=pm.group("sha"),
                pseudo=True,
                needs_verification=True,
            )
        else:
            entry = Entry(
                line=i,
                lhs=m2.group("lhs").strip(),
                target=m2.group("target").strip(),
                version=version,
                claimed_lineage=None,
                sha=None,
                pseudo=False,
                needs_verification=False,
            )
        out.append(entry)
    return out


def _git(cwd: Path, *args: str) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def verify_entry(entry: Entry, upstream_clone: Path) -> None:
    if not entry.pseudo or not entry.sha or not entry.claimed_lineage:
        return
    sha = entry.sha
    claimed = entry.claimed_lineage  # e.g. v8.5.2
    verification = {
        "upstream_clone": str(upstream_clone),
        "sha": sha,
        "claimed_lineage_tag": claimed,
    }
    rc_a, out_a, err_a = _git(upstream_clone, "cat-file", "-e", sha + "^{commit}")
    if rc_a != 0:
        verification["sha_present"] = False
        verification["error"] = err_a or "sha not in clone"
        entry.flagged = True
        entry.reason = "SHA not present in upstream clone"
        entry.verification = verification
        return
    verification["sha_present"] = True
    rc_b, out_b, _ = _git(upstream_clone, "describe", "--contains", "--all", sha)
    verification["describe_contains"] = out_b
    rc_c, out_c, _ = _git(upstream_clone, "merge-base", "--is-ancestor", sha, claimed)
    is_ancestor = rc_c == 0
    verification["is_ancestor_of_claimed"] = is_ancestor
    entry.verification = verification
    if not is_ancestor:
        # SHA does not descend from the claimed tag — version-prefix lies.
        entry.flagged = True
        entry.reason = (
            f"SHA {sha} is not an ancestor of claimed tag {claimed}; "
            f"describe={out_b or 'unknown'}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="D5 fork pseudo-version mislabel detector")
    ap.add_argument("gomod", help="path to go.mod")
    ap.add_argument("--out", help="write JSON to this path")
    ap.add_argument("--verify", action="store_true",
                    help="run stage 2 git verification (requires --upstream-clone)")
    ap.add_argument("--upstream-clone",
                    help="path to upstream repo clone for verify mode")
    args = ap.parse_args(argv)

    gomod_path = Path(args.gomod)
    if not gomod_path.is_file():
        print(json.dumps({"schema": SCHEMA, "error": "go.mod not found", "path": str(gomod_path)}))
        return 2

    entries = parse_go_mod(gomod_path)

    if args.verify:
        if not args.upstream_clone:
            print(json.dumps({
                "schema": SCHEMA,
                "error": "--verify requires --upstream-clone <path>",
            }))
            return 2
        clone = Path(args.upstream_clone)
        if not clone.is_dir():
            print(json.dumps({
                "schema": SCHEMA,
                "error": "upstream clone path is not a directory",
                "path": str(clone),
            }))
            return 2
        for e in entries:
            if e.pseudo:
                verify_entry(e, clone)
                e.needs_verification = False

    pseudo_count = sum(1 for e in entries if e.pseudo)
    flagged = [asdict(e) for e in entries if e.flagged]
    payload = {
        "schema": SCHEMA,
        "go_mod": str(gomod_path),
        "stage": "verify" if args.verify else "offline",
        "count_replace_entries": len(entries),
        "count_pseudo_versions": pseudo_count,
        "count_flagged": len(flagged),
        "entries": [asdict(e) for e in entries],
        "flagged": flagged,
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
