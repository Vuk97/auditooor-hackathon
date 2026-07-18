#!/usr/bin/env python3
"""
detector-tier-mover.py — apply a tier change to detectors/_tier_registry.yaml.

Unlike tools/detector-promote.py (Phase 12, read-only proposals), this tool
actually rewrites the registry: it flips the `tier:` field for a given
detector atomically (temp file + fsync + rename), appends an entry to
detectors/_tier_registry_audit.log, and re-parses the YAML afterward to
prove it still loads.

This commit ships the tool; moves are a separate operation — nothing is
written unless you invoke it with real arguments (and even then --dry-run
keeps the registry untouched).

Usage:
    detector-tier-mover.py --det r94_loop_foo --from E --to D \\
                           [--reason "regression on wave16"] [--dry-run]
    detector-tier-mover.py --bulk moves.yaml [--dry-run]

Bulk file format (YAML or a minimal dict-list the stdlib regex fallback
can parse; one entry per detector):
    - det: r94_loop_foo
      from: E
      to:   D
      reason: regression on wave16
    - det: abi-encode-packed-hash-collision
      from: D
      to:   E
      reason: fixture pair re-added
"""
from __future__ import annotations
import argparse
import datetime as _dt
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = REPO_ROOT / "detectors" / "_tier_registry.yaml"
AUDIT_LOG = REPO_ROOT / "detectors" / "_tier_registry_audit.log"
VALID_TIERS = {"S", "E", "A", "B", "C", "D"}

try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:
    _HAVE_YAML = False


# ── registry I/O ────────────────────────────────────────────────────────────

def _read_registry_text() -> str:
    if not REGISTRY.exists():
        sys.exit(f"[tier-mover] registry not found: {REGISTRY}")
    return REGISTRY.read_text()


def _find_entry(text: str, det: str) -> tuple[int, int, str] | None:
    """Locate the `tier: X` line for detector `det`.

    Returns (line_start_offset, line_end_offset, current_tier) or None.
    Registry format is regular enough for regex: each detector is a top-level
    key under `tiers:`, indented 2 spaces; its `tier:` child is indented 4.
    """
    # anchor on the detector header line, then the next `    tier: X` line.
    header_re = re.compile(rf"^  {re.escape(det)}:\s*$", re.MULTILINE)
    m = header_re.search(text)
    if not m:
        return None
    tail = text[m.end():]
    tier_re = re.compile(r"^    tier:\s*([A-Za-z])\s*$", re.MULTILINE)
    tm = tier_re.search(tail)
    if not tm:
        return None
    # confirm no other detector header appears between header and tier line.
    between = tail[:tm.start()]
    if re.search(r"^  \S", between, re.MULTILINE):
        return None
    abs_start = m.end() + tm.start()
    abs_end = m.end() + tm.end()
    return abs_start, abs_end, tm.group(1).upper()


def _write_atomic(path: Path, content: str) -> None:
    d = path.parent
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _validate_yaml(text: str) -> None:
    if _HAVE_YAML:
        yaml.safe_load(text)  # will raise on malformed
        return
    # stdlib fallback: check every non-blank line is either top-level key,
    # 2-space-indented header, 4-space-indented child, or 4-space list item.
    for i, ln in enumerate(text.splitlines(), 1):
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][\w-]*:", ln):
            continue
        if re.match(r"^ {2}\S", ln) or re.match(r"^ {4}\S", ln) or re.match(r"^ {4}- ", ln):
            continue
        raise ValueError(f"line {i}: unexpected indent/shape: {ln!r}")


def _audit(det: str, frm: str, to: str, reason: str) -> str:
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    reason_s = f" (reason: {reason})" if reason else ""
    return f"[{ts}] MOVE {det}: {frm} → {to}{reason_s}\n"


# ── core move ───────────────────────────────────────────────────────────────

def apply_move(det: str, frm: str, to: str, reason: str, *, dry_run: bool) -> int:
    frm, to = frm.upper(), to.upper()
    for label, t in (("--from", frm), ("--to", to)):
        if t not in VALID_TIERS:
            print(f"[tier-mover] {label}={t} not in {sorted(VALID_TIERS)}", file=sys.stderr)
            return 1
    if frm == to:
        print(f"[tier-mover] noop: {det} already {frm}", file=sys.stderr)
        return 1

    text = _read_registry_text()
    loc = _find_entry(text, det)
    if loc is None:
        print(f"[tier-mover] detector not found in registry: {det}", file=sys.stderr)
        return 1
    start, end, current = loc
    if current != frm:
        print(f"[tier-mover] {det} is tier {current}, not {frm}", file=sys.stderr)
        return 1

    new_line = f"    tier: {to}"
    new_text = text[:start] + new_line + text[end:]

    try:
        _validate_yaml(new_text)
    except Exception as e:
        print(f"[tier-mover] refusing write — YAML would be invalid: {e}", file=sys.stderr)
        return 1

    audit_line = _audit(det, frm, to, reason)
    if dry_run:
        print(f"[dry-run] would move {det}: {frm} → {to}")
        print(f"[dry-run] audit: {audit_line.rstrip()}")
        return 0

    _write_atomic(REGISTRY, new_text)
    with open(AUDIT_LOG, "a") as f:
        f.write(audit_line)
        f.flush()
        os.fsync(f.fileno())
    # re-parse from disk as final sanity check
    _validate_yaml(REGISTRY.read_text())
    print(f"[tier-mover] {det}: {frm} → {to}")
    return 0


def _load_bulk(path: Path) -> list[dict]:
    raw = path.read_text()
    if _HAVE_YAML:
        data = yaml.safe_load(raw) or []
        if not isinstance(data, list):
            sys.exit("[tier-mover] --bulk file must be a YAML list")
        return data
    # regex fallback: parse `- det: X` blocks
    entries, cur = [], None
    for ln in raw.splitlines():
        if ln.startswith("- "):
            if cur:
                entries.append(cur)
            cur = {}
            ln = ln[2:]
        if cur is None:
            continue
        m = re.match(r"\s*([a-z]+):\s*(.*?)\s*$", ln)
        if m:
            cur[m.group(1)] = m.group(2).strip('"\'')
    if cur:
        entries.append(cur)
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="apply a tier change to _tier_registry.yaml")
    ap.add_argument("--det")
    ap.add_argument("--from", dest="frm")
    ap.add_argument("--to")
    ap.add_argument("--reason", default="")
    ap.add_argument("--bulk", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if args.bulk:
        rc = 0
        for e in _load_bulk(args.bulk):
            try:
                rc |= apply_move(e["det"], str(e["from"]), str(e["to"]),
                                 e.get("reason", ""), dry_run=args.dry_run)
            except KeyError as k:
                print(f"[tier-mover] bulk entry missing field: {k}", file=sys.stderr)
                rc |= 1
        return rc

    if not (args.det and args.frm and args.to):
        ap.error("need --det/--from/--to, or --bulk")
    return apply_move(args.det, args.frm, args.to, args.reason, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
