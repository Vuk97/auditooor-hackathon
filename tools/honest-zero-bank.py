#!/usr/bin/env python3
# <!-- r36-rebuttal: lane W3b-honest-zero-bank registered via agent-pathspec-register.py -->
"""honest-zero-bank.py - bank the REUSABLE residue of a clean honest-0 run.

THE PROBLEM THIS FIXES
======================
A clean honest-0 (e.g. polygon: every fork file unmodified-upstream OOS, every
unit ruled out) currently banks NOTHING reusable for the next engagement. The
global memory anchor is blunt: the corpus is a WIRING-not-supply problem, and the
prior-audits / cross-ws-seed lanes are dormant. So when the SAME fork is re-pinned
next engagement, we re-resolve the fork bases, re-diff the upstream, and re-hunt
the same dead-ends from scratch - the prior verdict evaporated.

THE FIX
=======
At honest-0 time, write ONE engagement-level summary record (reusable across
engagements) into a cross-engagement seed file. The record captures the three
durable, replayable facts of a clean 0:

  1. per-drop_class dead-end counts - "we dropped N units as privileged-only /
     oos-unmodified-upstream / generic-dos this engagement" (via the SHARED
     classifier tools/lib/dead_end_classify, mined by tools/dead-end-ledger).
  2. the resolved fork bases - "<fork> = <owner>/<repo>@<ref>" (from
     <ws>/.auditooor/fork_bases.json) so a re-pin reuses the base instead of
     re-discovering it.
  3. per-fork unmodified-upstream OOS file counts - "<fork>: K modified,
     U unmodified-upstream OOS" (modified count from the fork-scope sidecar when
     present, else recomputed cheaply on-disk via tools/lib/fork_modified;
     unmodified = total in-scope source files minus modified).

The seed file is reports/honest_zero_bank.jsonl (one record per workspace,
schema auditooor.honest_zero_bank.v1). IDEMPOTENT: keyed by workspace name; a
re-run REPLACES that workspace's record rather than appending a duplicate.

COMPLETENESS-SAFE: every input is best-effort. A missing dead-end ledger / absent
fork_bases.json / unresolvable fork base degrades GRACEFULLY (the corresponding
section is empty + a recorded reason), never a crash and never a false claim of a
banked dead-end where none exists.

CLI:
    honest-zero-bank.py --workspace <ws> [--bank-file PATH] [--json] [--quiet]
Exit:
    0  record written (even when degraded - degraded is recorded, not fatal)
    2  usage error (missing/invalid workspace)
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.honest_zero_bank.v1"

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent
# Default cross-engagement seed location (one record per workspace).
DEFAULT_BANK_FILE = REPO_ROOT / "reports" / "honest_zero_bank.jsonl"


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Reuse the SHARED dead-end miner (which itself composes the shared classifier
# tools/lib/dead_end_classify). Do NOT reimplement drop-class classification.
# --------------------------------------------------------------------------
def _load_module(name: str, fname: str):
    spec = importlib.util.spec_from_file_location(name, str(_HERE / fname))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _dead_end_class_counts(ws: Path) -> Tuple[Dict[str, int], int, str]:
    """Per-drop_class counts of ruled-out units, mined from the sidecars by the
    shared tools/dead-end-ledger (which uses lib/dead_end_classify).

    Returns ``(class_counts, total, reason)``. ``reason`` is "" on success or a
    short degrade note (empty counts) - never raises.
    """
    try:
        ledger = _load_module("_hzb_dead_end_ledger", "dead-end-ledger.py")
    except Exception as exc:  # pragma: no cover - defensive
        return {}, 0, f"dead-end-ledger-unavailable:{type(exc).__name__}"
    try:
        rows = ledger.build_ledger(ws)
    except Exception as exc:  # pragma: no cover - defensive
        return {}, 0, f"build_ledger-error:{type(exc).__name__}"
    counts: Counter = Counter()
    for r in rows:
        counts[str(r.get("drop_class") or "ruled-out-other")] += 1
    return dict(counts), len(rows), ""


def _load_fork_modified_lib():
    """Import tools/lib/fork_modified (shared multi-lang diff lib). None on failure."""
    lib_path = _HERE / "lib" / "fork_modified.py"
    if not lib_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_hzb_fork_modified", str(lib_path))
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # pragma: no cover - defensive
        return None


def _fork_scope_modified_by_name(ws: Path) -> Dict[str, Optional[int]]:
    """Read per-fork modified-file counts from the fork-scope sidecar when the
    in-scope emitter already stamped one (no re-clone needed).

    Returns ``{local_name: modified_file_count_or_None}``; None means the emitter
    kept-all (unresolved/clone-failed) so an OOS count cannot be asserted.
    Absent sidecar => empty dict.
    """
    sidecar = _load_json(ws / "inscope_units.fork_scope.json")
    if not isinstance(sidecar, dict):
        # the emitter also writes it next to the manifest under .auditooor; try both
        sidecar = _load_json(ws / ".auditooor" / "inscope_units.fork_scope.json")
    out: Dict[str, Optional[int]] = {}
    if not isinstance(sidecar, dict):
        return out
    for fk in sidecar.get("forks") or []:
        if not isinstance(fk, dict):
            continue
        name = str(fk.get("local_name") or "")
        if not name:
            continue
        mc = fk.get("modified_file_count")
        out[name] = mc if isinstance(mc, int) else None
    return out


def _fork_oos_counts(ws: Path, fork_bases: List[dict]) -> Tuple[List[dict], str]:
    """For each resolved fork base, record modified vs unmodified-upstream OOS
    source-file counts.

    modified count: prefer the fork-scope sidecar (already computed by the
    in-scope emitter); else None (we never re-clone the upstream here - that is
    the emitter's job, and a re-clone in the bank step would be heavy + network
    dependent). total in-scope source files: counted cheaply on-disk over the
    fork checkout via the SHARED lib/fork_modified._source_files. unmodified OOS =
    total - modified (only when modified is known; else recorded as None).

    Returns ``(rows, reason)``; degrades gracefully.
    """
    rows: List[dict] = []
    fm = _load_fork_modified_lib()
    sidecar_modified = _fork_scope_modified_by_name(ws)
    reason = ""
    if fm is None:
        reason = "fork_modified-lib-unavailable"
    for fr in fork_bases:
        if not isinstance(fr, dict):
            continue
        name = str(fr.get("local_name") or "")
        if not name:
            continue
        fork_dir = ws / "src" / name
        total_src: Optional[int] = None
        if fm is not None and fork_dir.is_dir():
            try:
                total_src = len(
                    fm._source_files(
                        fork_dir,
                        extensions=fm.DEFAULT_SOURCE_EXTENSIONS,
                        skip_tests=True,
                    )
                )
            except Exception:  # pragma: no cover - defensive
                total_src = None
        modified = sidecar_modified.get(name)
        unmodified_oos: Optional[int] = None
        if isinstance(total_src, int) and isinstance(modified, int):
            unmodified_oos = max(0, total_src - modified)
        rows.append({
            "local_name": name,
            "upstream_repo": str(fr.get("upstream_repo") or ""),
            "base_ref": str(fr.get("base_ref") or ""),
            "resolved_via": str(fr.get("resolved_via") or ""),
            "in_scope_source_files": total_src,
            "modified_file_count": modified,
            "unmodified_upstream_oos_file_count": unmodified_oos,
        })
    return rows, reason


def _mutation_verified_invariant_count(ws: Path) -> int:
    """Count genuine, real-CUT-bound, mutation-verified harnesses banked this
    engagement (a clean 0 with deep coverage still has reusable INVARIANT seeds).

    Reuses honest-zero-verify's UN-FAKEABLE counters (killed + non-vacuous + CUT
    on disk) so the bank cannot over-credit: aggregate per_function entries
    corroborated as genuine, PLUS standalone v1 sidecars. 0 on any failure.
    """
    try:
        hzv = _load_module("_hzb_hzv", "honest-zero-verify.py")
    except Exception:  # pragma: no cover - defensive
        return 0
    try:
        agg = hzv._corroborated_genuine_count(ws)
        side = hzv._standalone_verified_count(ws)
        return int(agg) + int(side)
    except Exception:  # pragma: no cover - defensive
        return 0


def build_record(ws: Path) -> Dict[str, Any]:
    """Build the engagement-level honest-0 bank record (reusable, idempotent)."""
    degraded_reasons: List[str] = []

    dead_class_counts, dead_total, dead_reason = _dead_end_class_counts(ws)
    if dead_reason:
        degraded_reasons.append(f"dead_ends:{dead_reason}")

    fork_bases = _load_json(ws / ".auditooor" / "fork_bases.json")
    if not isinstance(fork_bases, list):
        fork_bases = []
        degraded_reasons.append("fork_bases:absent-or-malformed")
    fork_rows, fork_reason = _fork_oos_counts(ws, fork_bases)
    if fork_reason:
        degraded_reasons.append(f"fork_oos:{fork_reason}")

    invariant_seed_count = _mutation_verified_invariant_count(ws)

    # The bank is "non-empty" (a genuinely reusable record) when ANY of the three
    # durable residues exists: a ruled-out unit, a resolved fork base, or a
    # mutation-verified invariant seed.
    reusable_total = dead_total + len(fork_rows) + invariant_seed_count

    record: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": _now_utc(),
        "workspace": ws.name,
        "workspace_path": str(ws),
        "dead_end_class_counts": dead_class_counts,
        "dead_end_total": dead_total,
        "fork_bases": fork_rows,
        "fork_base_count": len(fork_rows),
        "mutation_verified_invariant_seed_count": invariant_seed_count,
        "reusable_record_count": reusable_total,
        "degraded": bool(degraded_reasons),
        "degraded_reasons": degraded_reasons,
    }
    return record


def _read_bank(bank_file: Path) -> List[Dict[str, Any]]:
    """Read existing bank records (one JSON object per line). Malformed lines are
    WARN-skipped, never silently lost."""
    rows: List[Dict[str, Any]] = []
    if not bank_file.is_file():
        return rows
    try:
        for ln, line in enumerate(bank_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except ValueError as exc:
                _eprint(f"[WARN] honest-zero-bank: skipping malformed {bank_file}:{ln}: {exc}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    except OSError as exc:  # pragma: no cover - defensive
        _eprint(f"[WARN] honest-zero-bank: cannot read {bank_file}: {exc}")
    return rows


def write_record(record: Dict[str, Any], bank_file: Path) -> Path:
    """Idempotently upsert ``record`` into the cross-engagement bank file, keyed by
    workspace. Re-running for the same workspace REPLACES its record."""
    bank_file.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_bank(bank_file)
    ws_key = record.get("workspace")
    merged = [r for r in existing if r.get("workspace") != ws_key]
    merged.append(record)
    # stable order by workspace for byte-stable idempotency
    merged.sort(key=lambda r: str(r.get("workspace") or ""))
    bank_file.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in merged),
        encoding="utf-8",
    )
    return bank_file


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True,
                    help="workspace path (the dir containing .auditooor/)")
    ap.add_argument("--bank-file", default=str(DEFAULT_BANK_FILE),
                    help="cross-engagement seed file (default reports/honest_zero_bank.jsonl)")
    ap.add_argument("--json", action="store_true", help="print the record JSON to stdout")
    ap.add_argument("--quiet", action="store_true", help="suppress the human summary line")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.is_dir():
        _eprint(f"[honest-zero-bank] ERR workspace not found: {ws}")
        return 2

    record = build_record(ws)
    bank_file = Path(os.path.expanduser(args.bank_file)).resolve()
    write_record(record, bank_file)

    if args.json:
        print(json.dumps(record, indent=2))
    if not args.quiet:
        degraded = " (DEGRADED)" if record["degraded"] else ""
        _eprint(
            f"[honest-zero-bank] {ws.name}: dead_ends={record['dead_end_total']} "
            f"fork_bases={record['fork_base_count']} "
            f"invariant_seeds={record['mutation_verified_invariant_seed_count']} "
            f"-> reusable={record['reusable_record_count']}{degraded}"
        )
        _eprint(f"[honest-zero-bank] wrote {bank_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
