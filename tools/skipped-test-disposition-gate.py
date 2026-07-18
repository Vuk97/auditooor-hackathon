#!/usr/bin/env python3
"""skipped-test-disposition-gate.py - fail-closed gate over discovered skipped tests.

The discovery scanner (skipped-test-marker-scan.py) MINES the project's own
skipped/disabled tests as developer-confessed seeds. This gate ENFORCES that
every such seed was carried into the per-function hunt (or explicitly rebutted
by the operator). A skipped test names a behavior the team turned off; a
workspace that never even looked at those behaviors during the hunt is NOT DONE.

Mirrors scanner-ran-integrity.py + the FIXME/self-ack disposition pattern:
  - importable ``evaluate(ws) -> dict`` for audit-done-guard to chain via
    importlib (same spec_from_file_location pattern the guard already uses for
    honest-zero-verify / readme-conformance-check); fail-OPEN on a tool import
    error, fail-CLOSED on a loaded non-pass result.
  - CLI: --workspace/--ws, --check (exit 1 on fail), --json.

DISPOSITION CONTRACT - a row is DISPOSED iff one of:
  (a) HUNTED   - a hunt sidecar under <ws>/.auditooor/hunt_findings_sidecars/*.json
                 whose anchor file resolves to the row's exercises_file OR
                 exercises_inscope_unit (path-normalized), status in
                 (ok, confirmed, negative).
  (b) REBUTTED - a typed line in <ws>/.auditooor/skipped_test_rebuttals.txt of
                 form ``rebut: <file>:<line>: <reason>`` (mirrors
                 readme_step_waivers.txt / the l37-rebuttal convention).

VERDICTS:
  pass-skipped-tests-disposed       (rc 0) - artifact present, fresh, all rows disposed
                                              (incl. the trivially-true n_rows==0 case)
  fail-scan-not-run                 (rc 1) - no skipped_test_markers.jsonl (absence != zero)
  fail-scan-stale                   (rc 1, STRICT only) - CUT changed since last scan
  fail-skipped-tests-undisposed     (rc 1) - >=1 open obligation; open_rows enumerates each

A ``warn-attribution-unresolved`` advisory is appended (never blocks) when
disposed rows had best-effort (unresolved) attribution.

Usage:
  python3 tools/skipped-test-disposition-gate.py --workspace <ws> [--check] [--json] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

SCHEMA = "auditooor.skipped_test_disposition_gate.v1"

ARTIFACT_REL = ".auditooor/skipped_test_markers.jsonl"
REBUTTAL_REL = ".auditooor/skipped_test_rebuttals.txt"
SIDECAR_DIR_REL = ".auditooor/hunt_findings_sidecars"
SCOPE_REL = "scope.json"

_DISPOSED_STATUSES = {"ok", "confirmed", "negative"}
_STALE_MARGIN_S = 5.0  # small tolerance; only gated under STRICT


def _norm_path(s: str) -> str:
    return str(s or "").replace("\\", "/").lstrip("./").lower()


def _read_rows(ws: Path) -> list[dict]:
    p = ws / ARTIFACT_REL
    rows: list[dict] = []
    if not p.is_file():
        return rows
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        pass
    return rows


def _hunted_anchors(ws: Path) -> set[str]:
    """Normalised set of file anchors that the per-function hunt actually touched."""
    out: set[str] = set()
    d = ws / SIDECAR_DIR_REL
    if not d.is_dir():
        return out
    for p in d.glob("*.json"):
        try:
            obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        status = str(obj.get("status") or "").lower()
        if status and status not in _DISPOSED_STATUSES:
            continue
        anchor = obj.get("function_anchor") or {}
        f = anchor.get("file") if isinstance(anchor, dict) else None
        fl = obj.get("file_line")
        for cand in (f, fl):
            if isinstance(cand, str) and cand.strip():
                norm = _norm_path(cand)
                # strip ":line" suffix if present
                if ":" in norm and norm.rsplit(":", 1)[1].isdigit():
                    norm = norm.rsplit(":", 1)[0]
                # also reduce an absolute path to its ws-relative tail
                ws_tail = _norm_path(str(ws))
                if ws_tail and norm.startswith(ws_tail + "/"):
                    norm = norm[len(ws_tail) + 1:]
                out.add(norm)
    return out


def _rebuttals(ws: Path) -> set[tuple[str, str]]:
    """Parse skipped_test_rebuttals.txt -> set of (normfile, line) rebutted."""
    out: set[tuple[str, str]] = set()
    p = ws / REBUTTAL_REL
    if not p.is_file():
        return out
    try:
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.lower().startswith("rebut:"):
                continue
            body = line.split(":", 1)[1].strip()  # "<file>:<line>: <reason>"
            # split off file:line (line is numeric) then reason
            parts = body.split(":")
            if len(parts) < 2:
                continue
            # find the numeric line token after the file path
            # file may itself contain no colon; format is <file>:<line>: <reason>
            f = parts[0].strip()
            ln = parts[1].strip().split()[0] if parts[1].strip() else ""
            if f and ln.isdigit():
                out.add((_norm_path(f), ln))
    except OSError:
        pass
    return out


def _anchor_matches(row: dict, hunted: set[str]) -> bool:
    cands = []
    for k in ("exercises_inscope_unit", "exercises_file"):
        v = row.get(k)
        if isinstance(v, str) and v.strip():
            norm = _norm_path(v)
            if ":" in norm and norm.rsplit(":", 1)[1].isdigit():
                norm = norm.rsplit(":", 1)[0]
            cands.append(norm)
    for c in cands:
        if c in hunted:
            return True
    return False


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _scope_or_src_mtime(ws: Path) -> float:
    """Newest mtime of scope.json (cheap freshness proxy for the CUT)."""
    return _mtime(ws / SCOPE_REL)


def evaluate(ws: Path, *, strict: bool = False) -> dict:
    ws = Path(ws)
    res = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "verdict": "",
        "n_rows": 0,
        "n_disposed": 0,
        "n_open": 0,
        "open_rows": [],
        "conformance_pass": False,
    }

    artifact = ws / ARTIFACT_REL
    if not artifact.is_file():
        res["verdict"] = "fail-scan-not-run"
        res["reason"] = (
            "no .auditooor/skipped_test_markers.jsonl - the discovery scanner never "
            "ran for this workspace (absence != zero; run "
            "`python3 tools/skipped-test-marker-scan.py --ws <ws>`)"
        )
        return res

    rows = _read_rows(ws)
    res["n_rows"] = len(rows)

    if strict:
        src_m = _scope_or_src_mtime(ws)
        art_m = _mtime(artifact)
        if src_m and (src_m - art_m) > _STALE_MARGIN_S:
            res["verdict"] = "fail-scan-stale"
            res["reason"] = (
                f"scope.json is newer than the skipped-test scan artifact by "
                f"{src_m - art_m:.0f}s; the CUT changed since the last scan - re-run discovery"
            )
            return res

    if not rows:
        res["verdict"] = "pass-skipped-tests-disposed"
        res["conformance_pass"] = True
        res["reason"] = "no skipped tests discovered - trivially disposed"
        return res

    hunted = _hunted_anchors(ws)
    rebutted = _rebuttals(ws)

    open_rows: list[dict] = []
    n_disposed = 0
    n_unresolved_disposed = 0
    for row in rows:
        f = _norm_path(row.get("file") or "")
        ln = str(row.get("line") or "")
        disposed = False
        if (f, ln) in rebutted:
            disposed = True
        elif _anchor_matches(row, hunted):
            disposed = True
        if disposed:
            n_disposed += 1
            if row.get("attribution") == "unresolved":
                n_unresolved_disposed += 1
        else:
            open_rows.append({
                "file": row.get("file"),
                "line": row.get("line"),
                "test_name": row.get("test_name"),
                "exercises_symbol": row.get("exercises_symbol"),
                "reason": "no hunt sidecar over exercised symbol and no typed rebuttal",
            })

    res["n_disposed"] = n_disposed
    res["n_open"] = len(open_rows)
    res["open_rows"] = open_rows

    if open_rows:
        enumerated = ", ".join(f"{r['file']}:{r['line']}" for r in open_rows[:20])
        res["verdict"] = "fail-skipped-tests-undisposed"
        res["conformance_pass"] = False
        res["reason"] = (
            f"{len(open_rows)} developer-confessed skipped test(s) are un-mined: "
            f"{enumerated}. Carry each into the per-function hunt (a sidecar over the "
            "exercised symbol) or add a typed rebuttal line "
            "`rebut: <file>:<line>: <reason>` to .auditooor/skipped_test_rebuttals.txt"
        )
        return res

    res["verdict"] = "pass-skipped-tests-disposed"
    res["conformance_pass"] = True
    res["reason"] = f"all {len(rows)} skipped test(s) disposed (hunted or rebutted)"
    if n_unresolved_disposed:
        res["advisory"] = (
            f"warn-attribution-unresolved: {n_unresolved_disposed} disposed row(s) "
            "had best-effort (unresolved) symbol attribution - hunter read the test body"
        )
    return res


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fail-closed disposition gate over developer-confessed skipped tests.")
    ap.add_argument("--workspace", "--ws", required=True, dest="workspace")
    ap.add_argument("--check", action="store_true", help="exit 1 on any non-pass verdict")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on a stale scan (scope.json newer than the artifact)")
    args = ap.parse_args()

    strict = args.strict or str(os.environ.get("AUDITOOOR_L37_STRICT", "")).strip() in ("1", "true", "True")

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[skipped-test-disposition-gate] ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    res = evaluate(ws, strict=strict)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[skipped-test-disposition-gate] verdict={res['verdict']}")
        print(f"  rows={res['n_rows']} disposed={res['n_disposed']} open={res['n_open']}")
        print(f"  {res.get('reason','')}")
        for r in res.get("open_rows", [])[:40]:
            print(f"  OPEN: {r['file']}:{r['line']} {r.get('test_name') or '?'} "
                  f"({r.get('exercises_symbol') or 'unresolved'})")
        if res.get("advisory"):
            print(f"  {res['advisory']}")

    if args.check and not res["conformance_pass"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
