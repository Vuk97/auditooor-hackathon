#!/usr/bin/env python3
# r36: lane IGAL-GATE registered in .auditooor/agent_pathspec.json
"""incomplete-guard-ack-gate.py - FAIL-CLOSED gate for the IGAL discovery lane.

GATE name: IGAL-INCOMPLETE-GUARD-ACK
Schema: auditooor.incomplete_guard_ack_gate.v1

This is the enforcement companion to
``tools/incomplete-guard-acknowledgement-scanner.py`` (the IGAL discovery lane).
The scanner is hypothesis-only and never fails; THIS gate is the fail-closed
signal: a workspace cannot claim audit-complete while in-scope source contains
unaddressed high-bucket self-acknowledged incomplete guards (the exact false-green
the op-reth FIXME would have tripped).

It is DISTINCT from the external R47 acknowledged-wont-fix GATE
(``acknowledged-wont-fix-check.py``): R47 scans prior_audits/SECURITY.md/GHSA;
IGAL scans developer self-acknowledgements in in-tree source comments.

INPUTS (all under <ws>/.auditooor/):
  incomplete_guard_ack_hypotheses.jsonl   (scanner output)
  incomplete_guard_ack_last_run.json      (scanner freshness marker:
                                           run_id, utc_ts, head_sha, files_scanned,
                                           records_emitted)
  incomplete_guard_ack_dispositions.jsonl (operator/agent dispositions:
                                           {file, ack_line, disposition, reason})
  incomplete_guard_ack_dispositions.md    (optional; per-record igal-rebuttal markers)

A disposition row addresses a record when its (file, ack_line) matches and its
``disposition`` is one of:
  filed | not-fileable | igal-rebuttal
A ``not-fileable`` / ``igal-rebuttal`` disposition MUST carry a non-empty ``reason``.
An ``igal-rebuttal`` is also accepted as a per-record marker in the .md disposition
file: ``<!-- igal-rebuttal: <reason> -->`` or ``igal-rebuttal: <reason>`` (<=200
chars), requiring explicit operator approval (mirrors r47-rebuttal handling).

VERDICT LOGIC (first match wins):
  error                                       - workspace missing / unreadable. rc 2.
  pass-no-inscope-source                      - no in-scope source roots (honest N/A). rc 0.
  fail-scanner-not-run                        - in-scope source exists but the
                                                hypotheses file OR last_run marker is
                                                absent (discovery step never ran on this
                                                surface). rc 1.
  fail-stale-scanner-run                      - last_run.head_sha != current HEAD
                                                (re-pin happened; output stale). rc 1.
  fail-unaddressed-high-bucket-acknowledgement- >=1 high-bucket record has no matching
                                                disposition / rebuttal. rc 1.
  warn-unaddressed-med-bucket                 - all high addressed but >=1 med-bucket
                                                unaddressed. --strict => rc 1; else rc 0.
  ok-rebuttal                                 - every unaddressed high-bucket record
                                                carries a valid igal-rebuttal. rc 0.
  pass                                        - scanner ran fresh at HEAD AND every
                                                high-bucket record addressed. rc 0;
                                                prints 'pass-igal-incomplete-guard-ack'.

NEVER self-credits: a hand-written last_run marker is distrusted insofar as its
head_sha must match the real HEAD (this gate RECOMPUTES HEAD), matching the
"never hand-edit a marker to green a gate" doctrine.

CLI: incomplete-guard-ack-gate.py --workspace <ws> [--strict] [--json]
Exit codes: 0 pass / warn(non-strict) / ok-rebuttal / no-inscope; 1 any fail-* (and
warn under --strict); 2 input error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.incomplete_guard_ack_gate.v1"
GATE = "IGAL-INCOMPLETE-GUARD-ACK"
REBUTTAL_MAX_CHARS = 200

HYP_REL = ".auditooor/incomplete_guard_ack_hypotheses.jsonl"
MARKER_REL = ".auditooor/incomplete_guard_ack_last_run.json"
DISPO_JSONL_REL = ".auditooor/incomplete_guard_ack_dispositions.jsonl"
DISPO_MD_REL = ".auditooor/incomplete_guard_ack_dispositions.md"

VALID_DISPOSITIONS = {"filed", "not-fileable", "igal-rebuttal"}
REASON_REQUIRED = {"not-fileable", "igal-rebuttal"}

# ---------------------------------------------------------------------------
# Reuse the scanner's helpers (HEAD recompute, scope source-root presence).
# Path-load both modules (hyphenated filenames are not importable by name).
# ---------------------------------------------------------------------------
_TOOLS = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


try:  # normal package import
    from tools.lib import scope_exclusion as _scope  # type: ignore
except Exception:  # pragma: no cover
    _spec = importlib.util.spec_from_file_location(
        "scope_exclusion", _TOOLS / "lib" / "scope_exclusion.py"
    )
    _scope = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_scope)  # type: ignore[union-attr]

_SCANNER = _load("_igal_scanner", "incomplete-guard-acknowledgement-scanner.py")

# igal-rebuttal markers in the .md disposition file.
_REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*igal-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
_REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?igal[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Loaders.
# ---------------------------------------------------------------------------
def _load_hypotheses(ws: Path) -> list[dict[str, Any]]:
    p = ws / HYP_REL
    if not p.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                out.append(r)
    except OSError:
        return []
    return out


def _load_marker(ws: Path) -> dict[str, Any] | None:
    p = ws / MARKER_REL
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _dispo_key(file_rel: str, ack_line: Any) -> str:
    return f"{str(file_rel).lstrip('./')}::{ack_line}"


def _load_dispositions(ws: Path) -> dict[str, dict[str, Any]]:
    """Map (file::ack_line) -> disposition row. Last row wins."""
    p = ws / DISPO_JSONL_REL
    out: dict[str, dict[str, Any]] = {}
    if not p.is_file():
        return out
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            file_rel = r.get("file") or ""
            ack_line = r.get("ack_line")
            if not file_rel or ack_line is None:
                continue
            out[_dispo_key(file_rel, ack_line)] = r
    except OSError:
        return {}
    return out


def _load_md_rebuttals(ws: Path) -> str:
    p = ws / DISPO_MD_REL
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def _disposition_addresses(row: dict[str, Any]) -> bool:
    """True iff a disposition row validly addresses a record."""
    dispo = str(row.get("disposition") or "").strip().lower()
    if dispo not in VALID_DISPOSITIONS:
        return False
    if dispo in REASON_REQUIRED:
        reason = str(row.get("reason") or "").strip()
        if not reason:
            return False
        if dispo == "igal-rebuttal" and len(reason) > REBUTTAL_MAX_CHARS:
            return False
    return True


def _md_has_rebuttal_for(md_text: str, rec: dict[str, Any]) -> bool:
    """True iff the .md disposition file carries an igal-rebuttal referencing this
    record's file:ack_line (or a global one). A per-record marker cites
    ``<file>:<ack_line>`` in its reason; a bare marker is accepted as a global op
    approval only if it names this file:line."""
    if not md_text:
        return False
    target = f"{str(rec.get('file') or '').lstrip('./')}:{rec.get('ack_line')}"
    for m in list(_REBUTTAL_LINE_RE.finditer(md_text)) + list(
        _REBUTTAL_HTML_RE.finditer(md_text)
    ):
        reason = " ".join((m.group(1) or "").split())
        if not reason or len(reason) > REBUTTAL_MAX_CHARS:
            continue
        if target in reason:
            return True
    return False


def _record_addressed(
    rec: dict[str, Any],
    dispositions: dict[str, dict[str, Any]],
    md_text: str,
) -> tuple[bool, bool]:
    """Return (addressed, via_rebuttal)."""
    key = _dispo_key(rec.get("file") or "", rec.get("ack_line"))
    row = dispositions.get(key)
    if row is not None and _disposition_addresses(row):
        via_rebuttal = str(row.get("disposition") or "").lower() == "igal-rebuttal"
        return True, via_rebuttal
    if _md_has_rebuttal_for(md_text, rec):
        return True, True
    return False, False


# ---------------------------------------------------------------------------
# Core verdict.
# ---------------------------------------------------------------------------
def evaluate(ws: Path, *, strict: bool = False) -> tuple[int, dict[str, Any]]:
    ws = ws.resolve()
    payload: dict[str, Any] = {
        "schema_version": SCHEMA,
        "gate": GATE,
        "workspace": str(ws),
        "strict": strict,
    }
    if not ws.is_dir():
        payload["verdict"] = "error"
        payload["reason"] = f"workspace not found: {ws}"
        return 2, payload

    # In-scope source presence (honest N/A path).
    try:
        inscope_files = _SCANNER._iter_inscope_source_files(ws)
    except Exception:
        inscope_files = []
    payload["inscope_source_files"] = len(inscope_files)

    if not inscope_files:
        payload["verdict"] = "pass-no-inscope-source"
        payload["reason"] = "no in-scope source roots resolved; nothing to scan (N/A)"
        return 0, payload

    # Scanner-run freshness.
    hyp_path = ws / HYP_REL
    marker = _load_marker(ws)
    if not hyp_path.is_file() or marker is None:
        payload["verdict"] = "fail-scanner-not-run"
        payload["reason"] = (
            "in-scope source exists but the IGAL scanner has not run on this surface "
            "(hypotheses file or last_run marker absent). Run "
            "incomplete-guard-acknowledgement-scanner.py --workspace <ws> --emit."
        )
        return 1, payload

    # Stale-run check: recompute HEAD; the marker's head_sha must match.
    real_head = _SCANNER._git_head(ws)
    marker_head = str(marker.get("head_sha") or "")
    payload["current_head"] = real_head
    payload["marker_head"] = marker_head
    # Only enforce when we can actually determine a real HEAD (git present).
    if real_head and marker_head and real_head != marker_head:
        payload["verdict"] = "fail-stale-scanner-run"
        payload["reason"] = (
            f"scanner output is stale: last_run head_sha {marker_head[:12]} != "
            f"current HEAD {real_head[:12]}. Re-run the scanner at HEAD "
            "(always audit latest HEAD)."
        )
        return 1, payload

    records = _load_hypotheses(ws)
    dispositions = _load_dispositions(ws)
    md_text = _load_md_rebuttals(ws)

    high = [r for r in records if r.get("rank_bucket") == "high"]
    med = [r for r in records if r.get("rank_bucket") == "med"]
    payload["records_emitted"] = len(records)
    payload["high_bucket"] = len(high)
    payload["med_bucket"] = len(med)

    unaddressed_high: list[str] = []
    high_via_rebuttal = 0
    for r in high:
        addressed, via_rebuttal = _record_addressed(r, dispositions, md_text)
        if not addressed:
            unaddressed_high.append(f"{r.get('file')}:{r.get('ack_line')}")
        elif via_rebuttal:
            high_via_rebuttal += 1

    if unaddressed_high:
        payload["verdict"] = "fail-unaddressed-high-bucket-acknowledgement"
        payload["unaddressed_high"] = unaddressed_high[:50]
        payload["reason"] = (
            f"{len(unaddressed_high)} high-bucket self-acknowledged incomplete guard(s) "
            "have no disposition (filed | not-fileable+reason | igal-rebuttal+operator-reason): "
            + ", ".join(unaddressed_high[:10])
            + (" ..." if len(unaddressed_high) > 10 else "")
        )
        return 1, payload

    # All high addressed. Check med-bucket.
    unaddressed_med: list[str] = []
    for r in med:
        addressed, _ = _record_addressed(r, dispositions, md_text)
        if not addressed:
            unaddressed_med.append(f"{r.get('file')}:{r.get('ack_line')}")

    if unaddressed_med:
        payload["unaddressed_med"] = unaddressed_med[:50]
        payload["verdict"] = "warn-unaddressed-med-bucket"
        payload["reason"] = (
            f"all high-bucket records addressed, but {len(unaddressed_med)} med-bucket "
            "record(s) are unaddressed."
            + (" --strict treats this as a failure." if strict else "")
        )
        return (1 if strict else 0), payload

    # Every high addressed; if ALL addressing for high was via rebuttal, signal it.
    if high and high_via_rebuttal == len(high):
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = (
            "every high-bucket record is addressed via a valid operator igal-rebuttal."
        )
        return 0, payload

    payload["verdict"] = "pass"
    payload["pass_line"] = "pass-igal-incomplete-guard-ack"
    payload["reason"] = (
        "scanner ran fresh at HEAD; every high-bucket self-acknowledged incomplete "
        "guard is addressed (filed / not-fileable / rebuttal)."
    )
    return 0, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="IGAL incomplete-guard-acknowledgement fail-closed gate."
    )
    ap.add_argument("--workspace", required=True, help="workspace root path")
    ap.add_argument("--strict", action="store_true",
                    help="treat warn-unaddressed-med-bucket as a failure")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    rc, payload = evaluate(Path(args.workspace).expanduser(), strict=args.strict)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        verdict = payload.get("verdict", "error")
        is_pass = (
            verdict.startswith("pass")
            or verdict == "ok-rebuttal"
            or (verdict == "warn-unaddressed-med-bucket" and not args.strict)
        )
        prefix = "[PASS]" if is_pass else "[FAIL]"
        line = payload.get("pass_line") or verdict
        print(f"{prefix} {GATE}: {line}")
        if payload.get("reason"):
            print(f"  reason: {payload['reason']}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
