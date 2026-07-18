#!/usr/bin/env python3
"""stale-pin-check.py - R007 (enforcement-gap 2026-07-03): is the local src/ checkout
actually AT the declared audit pin?

THE gap: no gate compared the local `src/<repo>` git HEAD to the pin declared in
.auditooor/pin_policy.json / SCOPE.md, so a stale-pin (or drifted) checkout could pass
every downstream coverage gate while the audit ran against DIFFERENT code than it claims
to (mis-scoped; R007 "always audit the deployed/declared pin"). This tool compares each
in-scope git clone's HEAD to the declared pin set and flags any mismatch.

Generic + workspace-driven (NEVER fetches): declared pins are read from
.auditooor/pin_policy.json (any *_pin / pin-ish value that is a 7-40 hex SHA) plus SCOPE.md
hex tokens. A repo is AT-PIN when its HEAD full-SHA prefix-matches a declared pin (either
direction, >=7 chars). Verdicts:
  pass        - every src git repo is at a declared pin (or no git repos / no pins to check)
  warn|FLAG   - >=1 src repo HEAD matches NO declared pin (stale/drifted checkout)
  error       - workspace missing

Advisory by default (rc 0). Under AUDITOOOR_STALE_PIN_STRICT=1 a mismatch is rc 1.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.stale_pin_check.v1"
_SHA_RE = re.compile(r"\b([0-9a-f]{7,40})\b", re.I)
# tokens that look like a sha but are almost never a commit (avoid false pins)
_NOT_SHA = {"deadbeef", "cafebabe", "feedface", "0000000", "1234567", "abcdef0"}


def _declared_pins(ws: Path) -> set[str]:
    pins: set[str] = set()
    pp = ws / ".auditooor" / "pin_policy.json"
    if pp.is_file():
        try:
            d = json.loads(pp.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            d = {}
        if isinstance(d, dict):
            for k, v in d.items():
                if not isinstance(v, str):
                    continue
                if "pin" in k.lower() or "commit" in k.lower():
                    for m in _SHA_RE.finditer(v):
                        pins.add(m.group(1).lower())
    scope = ws / "SCOPE.md"
    if scope.is_file():
        try:
            txt = scope.read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        # only harvest SHAs that appear near a pin/commit cue line (conservative)
        for line in txt.splitlines():
            if re.search(r"pin|commit|@[0-9a-f]{7,}", line, re.I):
                for m in _SHA_RE.finditer(line):
                    pins.add(m.group(1).lower())
    return {p for p in pins if p not in _NOT_SHA and not p.isdigit()}


def _src_repo_heads(ws: Path) -> list[tuple[str, str]]:
    """(repo_rel_path, HEAD_full_sha) for every git clone under src/."""
    out: list[tuple[str, str]] = []
    src = ws / "src"
    root = src if src.is_dir() else ws
    for gitdir in root.rglob(".git"):
        repo = gitdir.parent
        try:
            r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            continue
        head = (r.stdout or "").strip().lower()
        if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", head):
            try:
                rel = str(repo.relative_to(ws))
            except ValueError:
                rel = str(repo)
            out.append((rel, head))
    return out


def _prefix_match(head: str, pins: set[str]) -> bool:
    for p in pins:
        if head.startswith(p) or p.startswith(head[:len(p)]) or head[:len(p)] == p:
            return True
        # symmetric prefix (declared short pin vs full head, or vice versa)
        n = min(len(head), len(p))
        if n >= 7 and head[:n] == p[:n]:
            return True
    return False


def check(ws: Path) -> dict:
    ws = Path(ws)
    if not ws.is_dir():
        return {"schema": SCHEMA, "verdict": "error", "reason": f"not a dir: {ws}"}
    pins = _declared_pins(ws)
    heads = _src_repo_heads(ws)
    if not heads:
        return {"schema": SCHEMA, "verdict": "pass", "reason": "no src/ git clones to check",
                "declared_pins": sorted(pins), "repos": []}
    if not pins:
        return {"schema": SCHEMA, "verdict": "pass",
                "reason": "no declared pin in pin_policy.json / SCOPE.md - cannot check (advisory-neutral)",
                "declared_pins": [], "repos": [{"repo": r, "head": h[:12]} for r, h in heads]}
    mismatched = []
    repos_out = []
    for rel, head in heads:
        at_pin = _prefix_match(head, pins)
        repos_out.append({"repo": rel, "head": head[:12], "at_declared_pin": at_pin})
        if not at_pin:
            mismatched.append(rel)
    if mismatched:
        return {"schema": SCHEMA, "verdict": "FLAG",
                "reason": (f"{len(mismatched)} src repo(s) NOT at any declared pin (stale/drifted "
                           f"checkout - audit may be scoped to different code): {mismatched}"),
                "declared_pins": sorted(pins), "repos": repos_out, "mismatched": mismatched}
    return {"schema": SCHEMA, "verdict": "pass",
            "reason": "every src/ git clone is at a declared pin",
            "declared_pins": sorted(pins), "repos": repos_out}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = check(Path(a.workspace).expanduser())
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[stale-pin-check] {rep['verdict']}: {rep.get('reason','')}")
    strict = os.environ.get("AUDITOOOR_STALE_PIN_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    if rep["verdict"] in ("FLAG", "fail") and strict:
        return 1
    if rep["verdict"] == "error":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
