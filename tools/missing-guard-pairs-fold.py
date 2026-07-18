#!/usr/bin/env python3
"""missing-guard-pairs-fold.py - advisory depth-stage fold of the reactive L30
missing-guard enumerator over the STANDARD naming pairs into the proactive R81
sibling-asymmetry cert input.

r36-rebuttal: lane generic-wiring-fixes-2026-06-08 registered in .auditooor/agent_pathspec.json

Wired into `make audit-depth` BEFORE depth-certificate-build. For each standard
naming pair (claim/finalize, deposit/withdraw, mint/burn, lock/unlock) it runs
tools/missing-guard-callsite-enumerator.sh over the in-scope src tree treating
ONE arm's keyword as the guard-bearing name and the OTHER arm's keyword as the
protected-resource pattern. The enumerator's UNGUARDED line excerpts are folded
into `<ws>/.auditooor/sibling_guard_asymmetries.jsonl` as
`auditooor.sibling_path_guard_diff.v1` rows with verdict='asymmetry-candidate',
which is exactly what depth-certificate-build.py + exploit-queue.py already read.

LANGUAGE-AGNOSTIC: the enumerator auto-detects sol/go/rs/ts/py from the tree.

HONEST: this emits CANDIDATE rows for triage (per L30 step 6), never a proven
bug. The candidate_gap_id is content-stable so re-runs are idempotent (rows are
keyed + de-duplicated against what is already on disk).

RELATED TOOLS:
  - tools/sibling-path-guard-diff.py : the PRIMARY structural sibling-diff pass
    (AST-ish arm pairing). This fold tool is the COMPLEMENTARY grep-based pass
    using the L30 enumerator; both write the same file and de-dup against it.
  - tools/missing-guard-callsite-enumerator.sh : the reactive single-pair shell
    enumerator this tool drives over the standard pair list.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.sibling_path_guard_diff.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
ENUMERATOR = AUDITOOOR_ROOT / "tools" / "missing-guard-callsite-enumerator.sh"


# ---------------------------------------------------------------------------
# Shared scope-exclusion helper (single source of truth for OOS / vendored /
# generated / test classification, shared across every coverage / depth gate).
# Loaded by path (tools/lib has no __init__.py), mirroring the sibling-tool
# loaders used elsewhere in these gates. If the helper is unavailable the tool
# degrades to the shell enumerator's own --exclude-dir pass alone (fail-safe
# toward MORE coverage: a missing helper never silently drops in-scope source).
# ---------------------------------------------------------------------------
def _load_scope_exclusion():
    try:
        tool_path = Path(__file__).resolve().with_name("lib") / "scope_exclusion.py"
        if not tool_path.is_file():
            return None
        spec = importlib.util.spec_from_file_location("_mgpf_scope_exclusion", tool_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_mgpf_scope_exclusion"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_SCOPE_EXCL = _load_scope_exclusion()


def _is_oos(rel: str) -> bool:
    """True iff ``rel`` is out-of-scope (generated OR test OR vendored) per the
    shared single-source-of-truth scope-exclusion table. An OOS b-arm file is an
    OOS asymmetry candidate (the sibling-diff already inherits these as OOS
    pairs), so the row is dropped before folding. Returns False when the helper
    is unavailable (fail-safe: keep the candidate, i.e. MORE coverage)."""
    if _SCOPE_EXCL is None:
        return False
    try:
        return bool(_SCOPE_EXCL.is_oos(rel))
    except Exception:
        return False

# Standard naming pairs (guard-arm keyword, resource-arm keyword, pair label).
# Each pair is run in BOTH directions so an asymmetry on either arm surfaces.
STANDARD_PAIRS = [
    ("claim", "finalize", "claim/finalize"),
    ("deposit", "withdraw", "deposit/withdraw"),
    ("mint", "burn", "mint/burn"),
    ("lock", "unlock", "lock/unlock"),
]

# The "Per-file unguarded line excerpts" section emits a file header line
#   "  --- path/to/file.ext ---"
# followed by grep -n excerpt lines of the form
#   "    <line>:<content>"
# (the file comes from the header, the excerpt line carries only line+content).
_FILE_HDR_RE = re.compile(r"^\s*---\s+(\S.*?)\s+---\s*$")
_EXCERPT_RE = re.compile(r"^\s+(\d+):")


def _resolve_src_root(ws: Path) -> Path:
    """Pick the in-scope source root: <ws>/src if present, <ws>/external if
    present, else the workspace root. Generic + language-agnostic."""
    for cand in ("src", "external", "contracts", "crates"):
        p = ws / cand
        if p.is_dir():
            return p
    return ws


def run_enumerator(repo_root: Path, guard_kw: str, resource_kw: str) -> list[tuple[str, int, str]]:
    """Run the enumerator for one (guard, resource) keyword pair. Returns a list
    of (file, line, content) UNGUARDED excerpt rows. Returns [] on any failure
    or empty result (advisory: never raises)."""
    if not ENUMERATOR.is_file():
        return []
    # Use loose function-name keyword greps as both guard-name and resource.
    # The enumerator wraps GUARD in \b...\b, so to match a camelCase/snake_case
    # identifier like 'claimRewards' from the bare keyword 'claim' we append an
    # identifier-continuation fragment ('claim[A-Za-z0-9_]*'). The RESOURCE side
    # is used as a raw regex, so the bare keyword already matches as a substring.
    guard_pat = guard_kw + "[A-Za-z0-9_]*"
    resource_pat = resource_kw + "[A-Za-z0-9_]*"
    try:
        proc = subprocess.run(
            ["bash", str(ENUMERATOR), str(repo_root), guard_pat, resource_pat],
            capture_output=True, text=True, timeout=120,
        )
    except Exception:
        return []
    rows: list[tuple[str, int, str]] = []
    cur_file = None
    in_excerpts = False
    for line in proc.stdout.splitlines():
        if "Per-file unguarded line excerpts:" in line:
            in_excerpts = True
            continue
        if not in_excerpts:
            continue
        if line.startswith("=====") or "Triage instructions" in line:
            # excerpt section ended
            if "Triage instructions" in line:
                break
            continue
        m = _FILE_HDR_RE.match(line)
        if m:
            cur_file = m.group(1)
            continue
        m = _EXCERPT_RE.match(line)
        if m and cur_file:
            try:
                ln = int(m.group(1))
            except ValueError:
                continue
            rows.append((cur_file, ln, line.strip()))
    return rows


def _rel(ws: Path, p: str) -> str:
    try:
        return os.path.relpath(p, ws)
    except Exception:
        return p


def make_record(ws: Path, guard_kw: str, resource_kw: str, pair_label: str,
                b_file: str, b_line: int) -> dict:
    b_rel = _rel(ws, b_file)
    gap_id = "ASYM-PAIR-" + hashlib.sha1(
        f"{pair_label}|{guard_kw}|{resource_kw}|{b_rel}:{b_line}".encode()
    ).hexdigest()[:12]
    return {
        "schema": SCHEMA,
        "candidate_gap_id": gap_id,
        "pair": pair_label,
        "pair_kind": "standard-naming-pair",
        "shared_invariant_hint": (
            f"'{resource_kw}'-named path should mirror the guard(s) the sibling "
            f"'{guard_kw}'-named path enforces (standard {pair_label} pair)"
        ),
        "path_a": {"name": guard_kw, "file": "", "line": None},
        "path_b": {"name": resource_kw, "file": b_rel, "line": b_line},
        "guard_on_a_missing_on_b": [f"{guard_kw}-arm-guard"],
        "guard_on_b_missing_on_a": [],
        "file_lines": [f"{b_rel}:{b_line}"],
        "verdict": "asymmetry-candidate",
        "source": "missing-guard-pairs-fold",
    }


def fold(ws: Path, json_out: bool = False) -> dict:
    src_root = _resolve_src_root(ws)
    out_path = ws / ".auditooor" / "sibling_guard_asymmetries.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing candidate_gap_ids for idempotent de-dup.
    existing_ids: set[str] = set()
    if out_path.is_file():
        for raw in out_path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                r = json.loads(raw)
            except json.JSONDecodeError:
                continue
            gid = str(r.get("candidate_gap_id") or "")
            if gid:
                existing_ids.add(gid)

    new_records: list[dict] = []
    seen_new: set[str] = set()
    for guard_kw, resource_kw, label in STANDARD_PAIRS:
        # Direction 1: resource-arm sites missing the guard-arm guard.
        for direction in ((guard_kw, resource_kw), (resource_kw, guard_kw)):
            g, r = direction
            for b_file, b_line, _content in run_enumerator(src_root, g, r):
                # Single-source-of-truth OOS prune: an asymmetry candidate whose
                # b-arm file is vendored / generated / test infra is itself OOS
                # (the structural sibling-diff already inherits these as OOS
                # pairs). Drop it before folding so the depth-cert input is never
                # seeded by an out-of-scope surface. Done on the WORKSPACE-relative
                # path (not src-root-relative) so the helper's path-segment markers
                # see the full prefix (e.g. external/<dep>, contracts/@openzeppelin,
                # x/<m>/keeper/foo.pb.go). Fail-safe: helper-absent keeps the row.
                if _is_oos(_rel(ws, b_file)):
                    continue
                rec = make_record(ws, g, r, label, b_file, b_line)
                gid = rec["candidate_gap_id"]
                if gid in existing_ids or gid in seen_new:
                    continue
                seen_new.add(gid)
                new_records.append(rec)

    if new_records:
        with out_path.open("a", encoding="utf-8") as fh:
            for rec in new_records:
                fh.write(json.dumps(rec) + "\n")

    summary = {
        "schema": "auditooor.missing_guard_pairs_fold.v1",
        "workspace": ws.name,
        "src_root": str(src_root),
        "pairs_checked": len(STANDARD_PAIRS),
        "new_asymmetry_candidates": len(new_records),
        "already_present": len(existing_ids),
        "output": str(out_path),
    }
    if json_out:
        print(json.dumps(summary, indent=2))
    else:
        sys.stderr.write(
            f"[missing-guard-pairs-fold] {summary['new_asymmetry_candidates']} new "
            f"asymmetry-candidate row(s) folded into {out_path.name} "
            f"(src_root={src_root}, {len(STANDARD_PAIRS)} pairs)\n"
        )
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        sys.stderr.write(f"[missing-guard-pairs-fold] ERR workspace not found: {ws}\n")
        return 2
    fold(ws, json_out=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
