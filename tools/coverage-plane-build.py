#!/usr/bin/env python3
"""coverage-plane-build.py - materialize the (unit x impact-frame) coverage plane
as a durable, file-based artifact.

THE GAP THIS CLOSES: `vault_coverage_plane` (tools/vault-mcp-server.py) exposes a
bounded, on-demand READ over a workspace's coverage substrate (completeness_matrix.json,
coverage_report.json, agent_mechanism_verdicts, mechanism_dispositions.jsonl) via MCP.
That callable is invisible to file-based gates and never runs automatically - nothing
writes a durable `.auditooor/coverage_plane.jsonl`, so a workspace can have the JOIN
data available only through an interactive MCP call, never as an artifact a CI-style
gate or a later pipeline step can `test -f` / grep / diff over time.

WHAT THIS DOES: builds the (in-scope unit x applicable impact-frame) cross-product for
a workspace and writes ONE ROW PER CELL to `<ws>/.auditooor/coverage_plane.jsonl`
(schema `auditooor.coverage_plane.v1`), plus a summary JSON
(`<ws>/.auditooor/coverage_plane_summary.json`) with cells_total / cells_covered /
cells_open / cells_not_enumerated counts.

REUSE, NOT DUPLICATION: the (unit x frame) applicability JOIN and the per-cell status
derivation are the SAME algorithm `vault_coverage_plane` already surfaces (indirectly,
via completeness_matrix.json's mechanism_axis) and the SAME algorithm
completeness-matrix-build.py's brick-3 per-frame crediting uses. This tool imports
completeness-matrix-build.py as a module and calls its helpers directly:
  _perfile_asset_of        -> the per-FILE, language-agnostic asset-key derivation
                                (a pure relpath key, no solidity-only `src/`
                                assumption); this tool's own inscope loader reuses it
                                for the SAME asset_id a unit would land under via
                                completeness-matrix-build's own _load_inscope_perfile
                                (which this tool wraps + extends with file_line/lang
                                passthrough - see _load_inscope_perfile_with_line).
  _load_mechanism_library   -> impact -> mechanisms taxonomy inverted from the SAME
                                impact_hunting_methodology.yaml / SEVERITY.md-derived
                                seed vault_coverage_plane's completeness_matrix.json
                                source draws from.
  _inscope_impact_frames_for_lang -> the applicable-frame-per-language JOIN (an impact
                                frame applies to a unit iff >=1 of its mechanisms lists
                                that unit's language) - the exact join brick 2/3 use.
  _load_function_coverage, _hunt_examined_keys, _hunt_examined_frames,
  _dispatched_frames_by_fn, _is_fcc_filtered_nonentry -> the SAME per-unit
                                coverage-status signals _build_assets_axis draws on, so
                                a cell's status here matches what completeness_matrix.json
                                / vault_coverage_plane would report for the same unit.
No JOIN logic is reimplemented; only the row-materialization (unit x frame -> jsonl row)
is new, because nothing previously flattened the cross-product into a durable artifact.

Modes:
  (default)  build + write coverage_plane.jsonl + coverage_plane_summary.json, print
             the summary counts. Advisory only - does not fail the process and does not
             flip any `required:true` flag in readme_runbook_steps.json (a later step
             owns that once this is proven across workspaces).
  --check    build, then return rc 0 (pass-coverage-plane) / rc 1
             (fail-coverage-plane-*) ONLY under an explicit opt-in (see Enforcement
             below); otherwise --check still runs the build and prints the verdict but
             always returns rc 0, so this tool can be dropped into an existing runbook
             step without retroactively bricking a workspace certified before it
             existed.
  --json     emit the summary JSON to stdout instead of the human-readable form.

Enforcement (opt-in, fail-closed only when requested):
  AUDITOOOR_COVERAGE_PLANE_STRICT=1 (or STRICT=1 on the CLI) makes `--check` return
  rc 1 when the workspace has zero in-scope units, zero applicable frames, or write
  failed. Fail-closed only under this explicit env/flag; a workspace run without it
  NEVER regresses to a FAIL it did not previously see (there is no prior gate reading
  this artifact yet, so there is nothing to brick - but a future gate consuming this
  file should require the same opt-in pattern before treating it as blocking).

Language-agnostic: the unit denominator and language classification come from
inscope_units.jsonl's own `lang` field (falling back to completeness-matrix-build.py's
extension map) - no solidity-specific path assumption (`src/` collapsing is a
completeness-matrix-build.py legacy-asset concern, not used here; this tool's asset key
is `_perfile_asset_of`'s per-FILE denominator, a pure relpath key).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.coverage_plane.v1"

_CMB_PATH = Path(__file__).resolve().parent / "completeness-matrix-build.py"


def _load_cmb():
    """Import completeness-matrix-build.py as a module (hyphenated filename, so a
    normal `import` cannot reach it) and REUSE its (unit x frame) JOIN helpers rather
    than re-deriving the algorithm."""
    spec = importlib.util.spec_from_file_location("coverage_plane_cmb", _CMB_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load completeness-matrix-build.py from {_CMB_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("coverage_plane_cmb", mod)
    spec.loader.exec_module(mod)
    return mod


def _ws(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


def _strict_enabled(cli_strict: bool) -> bool:
    if cli_strict:
        return True
    return os.environ.get("AUDITOOOR_COVERAGE_PLANE_STRICT", "") not in ("", "0", "false", "no")


def _unit_status_for_frame(
    cmb: Any,
    ws: Path,
    file_ref: str,
    fn_name: str,
    frame: str,
    fn_cov: dict[str, str],
    hunt_examined: set,
    hunt_frames: dict[str, set],
    per_frame_active: bool,
    dispatched_frames: dict[str, set],
    required_frames_for_lang: set,
    fcc_terminal: bool,
) -> str:
    """Per-(unit, frame) status, reusing the SAME signal precedence
    completeness-matrix-build.py's _build_assets_axis uses for the (unit) status, but
    resolved down to a single frame: a frame is 'covered' when the unit has a
    per-frame hunt verdict sidecar for THAT frame, or (backward-compat, no per-frame
    sidecars anywhere in the ws) the unit has ANY hunt verdict or a terminal
    function_coverage_completeness.json entry. 'open' mirrors an explicit
    hollow/untouched fn_cov verdict. 'out-of-scope-fcc-filtered' reuses
    _is_fcc_filtered_nonentry (same fcc-terminal gate _build_assets_axis applies) so a
    confirmed non-entry unit (internal/private/view/pure/interface-signature) matches
    completeness_matrix.json's classification instead of reading as a false gap.
    Anything else is 'not-enumerated' (fail-closed - never a silent pass)."""
    key = f"{Path(file_ref).name}::{fn_name}"
    cov_status = fn_cov.get(key)
    if per_frame_active and fn_name in hunt_frames:
        examined = hunt_frames.get(fn_name, set())
        if frame in examined:
            return "covered"
        # a frame that was DISPATCHED for this fn but not yet examined is an open
        # obligation, not an absence - matches brick-3's fail-closed NOT-ENUMERATED
        # posture for a partial frame set (never silently pass an undispatched-looking
        # frame the seed explicitly queued).
        required = dispatched_frames.get(fn_name, set()) or required_frames_for_lang
        if frame in required:
            return "not-enumerated"
    if cov_status in ("covered", "covered-mutation-verified"):
        return "covered"
    if cov_status == "open":
        return "open"
    if fn_name in hunt_examined:
        return "covered"
    if cov_status is None and fcc_terminal and cmb._is_fcc_filtered_nonentry(ws, file_ref, fn_name):
        return "out-of-scope-fcc-filtered"
    return "not-enumerated"


def _load_inscope_perfile_with_line(cmb: Any, ws: Path) -> dict[str, list[dict[str, Any]]]:
    """Same per-FILE asset grouping as completeness-matrix-build.py's
    _load_inscope_perfile (reuses its _perfile_asset_of key derivation - the JOIN
    algorithm - so a unit lands under the exact same asset_id), but additionally
    carries `file_line` and `lang` through from the raw row. _load_inscope_perfile
    itself drops both fields, and inscope_units.jsonl can legitimately have two
    DISTINCT rows for the same (file, function) - e.g. an overloaded/duplicate-named
    function declared at two different lines in the same file (observed on strata:
    Accounting.sol::totalAssets at both :148 and :164) - so file_line is required to
    disambiguate the unit key; without it two real units silently collapse into one
    `units_seen` entry even though both still emit rows (a units_total undercount)."""
    out: dict[str, list[dict[str, Any]]] = {}
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rel = r.get("file") or r.get("path") or ""
        asset = cmb._perfile_asset_of(rel)
        if not asset:
            continue
        out.setdefault(asset, []).append({
            "function": r.get("function") or r.get("fn") or r.get("name") or "",
            "file": rel,
            "file_line": r.get("file_line") or "",
            "lang": str(r.get("lang") or "").strip().lower(),
        })
    return out


def build_plane(ws: Path) -> dict[str, Any]:
    """Compute the (unit x frame) cell list + summary. Pure function over the
    workspace's existing `.auditooor/` artifacts; writes nothing (see main())."""
    cmb = _load_cmb()
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    inscope_raw = _load_inscope_perfile_with_line(cmb, ws)  # per-FILE, language-agnostic
    mech_lib = cmb._load_mechanism_library(ws)
    fn_cov, fcc_terminal = cmb._load_function_coverage(ws)
    hunt_examined = cmb._hunt_examined_keys(ws)
    hunt_frames = cmb._hunt_examined_frames(ws)
    per_frame_active = bool(hunt_frames)
    dispatched_frames = cmb._dispatched_frames_by_fn(ws) if per_frame_active else {}

    rows: list[dict[str, Any]] = []
    by_status: dict[str, int] = {}
    by_frame: dict[str, int] = {}
    units_seen: set[str] = set()
    frames_seen: set[str] = set()
    required_frames_cache: dict[str, set] = {}

    for asset_id, units in sorted(inscope_raw.items()):
        for u in units:
            file_ref = str(u.get("file") or "")
            fn_name = str(u.get("function") or "")
            file_line = str(u.get("file_line") or "")
            lang = str(u.get("lang") or "").strip().lower() or cmb._lang_of_unit_file(file_ref)
            if lang not in required_frames_cache:
                required_frames_cache[lang] = cmb._inscope_impact_frames_for_lang(lang, mech_lib)
            frames = required_frames_cache[lang]
            # disambiguate with file_line when present: inscope_units.jsonl can carry
            # two distinct rows for the same (file, function) - e.g. an
            # overloaded/duplicate-named declaration at different lines - and each is a
            # separate callable unit, not a duplicate.
            unit_key = f"{file_ref}::{fn_name}::{file_line}" if file_line else f"{file_ref}::{fn_name}"
            units_seen.add(unit_key)
            if not frames:
                # no applicable impact frame for this unit's language (e.g. an
                # unrecognized/extension-less file) - still emit ONE not-enumerated
                # row per unit so the unit is never silently absent from the plane.
                row = {
                    "schema": SCHEMA,
                    "ws_name": ws.name,
                    "unit": unit_key,
                    "asset": asset_id,
                    "file": file_ref,
                    "function": fn_name,
                    "lang": lang or None,
                    "frame": None,
                    "frame_kind": "impact",
                    "status": "not-enumerated",
                    "source_of_truth": "coverage-plane-build:no-applicable-frame",
                    "generated_at_utc": ts,
                }
                rows.append(row)
                by_status["not-enumerated"] = by_status.get("not-enumerated", 0) + 1
                continue
            for frame in sorted(frames):
                frames_seen.add(frame)
                status = _unit_status_for_frame(
                    cmb, ws, file_ref, fn_name, frame, fn_cov, hunt_examined,
                    hunt_frames, per_frame_active, dispatched_frames, frames,
                    fcc_terminal,
                )
                row = {
                    "schema": SCHEMA,
                    "ws_name": ws.name,
                    "unit": unit_key,
                    "asset": asset_id,
                    "file": file_ref,
                    "function": fn_name,
                    "lang": lang or None,
                    "frame": frame,
                    "frame_kind": "impact",
                    "status": status,
                    "source_of_truth": "completeness-matrix-build:_inscope_impact_frames_for_lang",
                    "generated_at_utc": ts,
                }
                rows.append(row)
                by_status[status] = by_status.get(status, 0) + 1
                by_frame[frame] = by_frame.get(frame, 0) + 1

    cells_total = len(rows)
    cells_covered = by_status.get("covered", 0)
    cells_open = by_status.get("open", 0)
    cells_not_enumerated = by_status.get("not-enumerated", 0)
    cells_out_of_scope = by_status.get("out-of-scope-fcc-filtered", 0)

    digest = hashlib.sha256(
        json.dumps(
            {"schema": SCHEMA, "ws": str(ws), "rows": [
                (r["unit"], r["frame"], r["status"]) for r in rows
            ]},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    summary = {
        "schema": SCHEMA + ".summary",
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "ws_name": ws.name,
        "generated_at_utc": ts,
        "units_total": len(units_seen),
        "frames_total": len(frames_seen),
        "cells_total": cells_total,
        "cells_covered": cells_covered,
        "cells_open": cells_open,
        "cells_not_enumerated": cells_not_enumerated,
        "cells_out_of_scope": cells_out_of_scope,
        "by_status": by_status,
        "by_frame": by_frame,
    }

    return {"rows": rows, "summary": summary}


def write_plane(ws: Path, result: dict[str, Any]) -> tuple[Path, Path]:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    plane_path = auditooor_dir / "coverage_plane.jsonl"
    summary_path = auditooor_dir / "coverage_plane_summary.json"
    with plane_path.open("w", encoding="utf-8") as fh:
        for row in result["rows"]:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    summary_path.write_text(
        json.dumps(result["summary"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return plane_path, summary_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True,
                     help="workspace root (contains .auditooor/)")
    ap.add_argument("--check", action="store_true",
                     help="build + print pass/fail verdict; rc 1 only under STRICT opt-in")
    ap.add_argument("--json", action="store_true", help="emit summary JSON to stdout")
    ap.add_argument("--strict", action="store_true",
                     help="opt-in fail-closed posture (same as AUDITOOOR_COVERAGE_PLANE_STRICT=1)")
    args = ap.parse_args(argv)

    ws = _ws(args.workspace)
    if not ws.is_dir():
        print(f"fail-coverage-plane-workspace-missing: {ws}", file=sys.stderr)
        return 1

    result = build_plane(ws)
    plane_path, summary_path = write_plane(ws, result)
    summary = result["summary"]

    strict = _strict_enabled(args.strict)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"coverage-plane-build: {ws.name}")
        print(f"  wrote {plane_path}")
        print(f"  wrote {summary_path}")
        print(f"  units_total={summary['units_total']} frames_total={summary['frames_total']}")
        print(f"  cells_total={summary['cells_total']} "
              f"cells_covered={summary['cells_covered']} "
              f"cells_open={summary['cells_open']} "
              f"cells_not_enumerated={summary['cells_not_enumerated']}")

    if args.check:
        fail = strict and (summary["cells_total"] == 0 or summary["units_total"] == 0)
        if fail:
            print("fail-coverage-plane-empty (STRICT)", file=sys.stderr)
            return 1
        print("pass-coverage-plane")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
