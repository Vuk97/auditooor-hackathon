#!/usr/bin/env python3
"""Fail-closed enforcement: every in-scope upstream owner/repo was actually mined.

gapA-multirepo-mining
=====================
PROBLEM (verified against real source): the mining DRIVER
``tools/audit-target-commit-mining.py`` derives its mine-set ONLY from
``targets.tsv`` rows and scope.json ``target_repos``/``targets``/... keys. It
never reconciles against scope.json ``in_scope`` SOURCE ROOTS. So a workspace
whose ``in_scope`` roots span genuinely separate git checkouts/owner-repos
silently mines only the targets.tsv subset - an in-scope upstream repo can be
NEVER mined and nothing flags it.

(For *optimism specifically* ``src/`` is ONE checkout of ethereum-optimism/
optimism and op-reth is VENDORED inside that monorepo at ``src/rust/op-reth``,
so one repo == full coverage there; but the driver has no mechanism that PROVES
this - it simply never looks at ``in_scope``. The fix is general.)

THIS TOOL is the standalone ENFORCEMENT layer (separate from the driver so it can
run in audit-complete even if the driver was skipped). It does NOT re-mine. It:

  1. reads scope.json ``in_scope`` -> resolves each source root to its upstream
     owner/repo (reusing the driver's ``inscope_owner_repos`` reconcile helper);
  2. reads the LATEST ``mining_rounds/<date>-...-commit-mining/
     commit_mining_manifest.json`` (newest by dir name) for the set of mined +
     skipped owner/repos and their statuses; cross-checks
     ``.auditooor/commit_lifecycle_ledger.json`` ``target_rows`` as a secondary
     source;
  3. for each REQUIRED in-scope owner/repo computes COVERED / SKIP-LOGGED /
     UNCOVERED and prints a machine-parseable final verdict line.

VERDICTS (final stdout line):
  pass-multi-repo-mining-coverage
      every required owner/repo COVERED and every in_scope root resolved.
  warn-multi-repo-mining-coverage: <repos>
      all required repos COVERED or SKIP-LOGGED but >=1 only SKIP-LOGGED, OR
      there are unresolved in_scope roots that ARE explicitly logged in the
      manifest. acceptable-but-degraded (honest logged skip).
  fail-multi-repo-mining-coverage: <uncovered owner/repos> | unlogged-unresolved-roots: <roots>
      >=1 required in-scope owner/repo UNCOVERED (silently never mined) OR an
      in_scope root failed to resolve AND has no logged skip row.
  pass-multi-repo-mining-coverage: no in_scope manifest (n/a)
      scope.json absent or in_scope empty (never block a non-multi-repo ws).

rc: 0 for pass/warn, 1 for fail. Under ``--strict`` a fail stays rc 1; a warn
stays rc 0 (honest logged skips never block - mirrors tier6-mining WARN-pass).
NEVER hand-writes a marker; recomputes from scope.json + manifest every run.

Composes with tools/lib/scope_exclusion.py (the shared scope filter) and imports
the reconcile helpers from audit-target-commit-mining.py via
``importlib.util.spec_from_file_location`` (the established pattern).
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = REPO_ROOT / "tools" / "audit-target-commit-mining.py"

# Manifest statuses that count as an explicit, honest, logged skip (no-silent-cap).
SKIP_LOGGED_STATUSES = {
    "skipped_no_gh_auth",
    "skipped_unresolved_upstream",
    "flattened_snapshot_prior_audit_pivot",
}
# Manifest statuses whose row is a real mining attempt that consumed a target.
COVERED_STATUSES = {"ok", "skipped_existing"}


def _load_driver():
    spec = importlib.util.spec_from_file_location(
        "audit_target_commit_mining", DRIVER_PATH
    )
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise RuntimeError(f"unable to load driver module: {DRIVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("audit_target_commit_mining", module)
    spec.loader.exec_module(module)
    return module


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _posint(v: Any) -> bool:
    """Genuine-ran predicate - mirrors check_tier6_mining._posint."""
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _genuine_ran_report(output_path_str: str, workspace: Path) -> bool:
    """A mining result with genuine-ran evidence.

    Mirrors check_tier6_mining: commits_scanned>0 OR security_fix_count>0 OR
    commit_count>0 OR a non-empty commits[].
    """
    if not output_path_str:
        return False
    candidates: list[Path] = []
    p = Path(output_path_str)
    if p.is_absolute():
        candidates.append(p)
    else:
        candidates.append(workspace / output_path_str)
        candidates.append(workspace / p.name)
    for cand in candidates:
        if not cand.is_file():
            continue
        payload = _load_json(cand)
        if not isinstance(payload, dict):
            continue
        if (
            _posint(payload.get("commits_scanned"))
            or _posint(payload.get("security_fix_count"))
            or _posint(payload.get("commit_count"))
            or (isinstance(payload.get("commits"), list) and len(payload["commits"]) > 0)
        ):
            return True
    return False


def _latest_manifest(workspace: Path) -> Path | None:
    """Newest mining_rounds/<dir>/commit_mining_manifest.json by dir name."""
    mining = workspace / "mining_rounds"
    if not mining.is_dir():
        return None
    try:
        round_dirs = sorted(
            (d for d in mining.iterdir() if d.is_dir() and not d.name.startswith(".")),
            key=lambda d: d.name,
        )
    except OSError:
        return None
    for rd in reversed(round_dirs):
        man = rd / "commit_mining_manifest.json"
        if man.is_file():
            return man
    return None


def _manifest_repo_statuses(workspace: Path) -> dict[str, dict[str, Any]]:
    """owner_repo -> {statuses:set, covered:bool, skip_logged:bool, rows:[...]}.

    Reads the latest manifest's rows plus, as a secondary source,
    .auditooor/commit_lifecycle_ledger.json target_rows. A repo is COVERED if any
    of its rows has status in COVERED_STATUSES AND a genuine-ran report (or a row
    that processed a target with genuine-ran evidence); SKIP-LOGGED if it has a
    logged-skip status row.
    """
    out: dict[str, dict[str, Any]] = {}

    def _record(owner_repo: str, status: str, output_path: str) -> None:
        if not owner_repo:
            return
        entry = out.setdefault(
            owner_repo, {"statuses": set(), "covered": False, "skip_logged": False}
        )
        entry["statuses"].add(status)
        if status in COVERED_STATUSES:
            if _genuine_ran_report(output_path, workspace):
                entry["covered"] = True
            else:
                # An ok/skipped_existing row whose report is missing/vacuous is
                # NOT genuine coverage; leave covered as-is (do not credit).
                pass
        if status in SKIP_LOGGED_STATUSES:
            entry["skip_logged"] = True

    man = _latest_manifest(workspace)
    if man is not None:
        payload = _load_json(man)
        if isinstance(payload, dict):
            rows = payload.get("rows")
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    _record(
                        str(row.get("owner_repo") or ""),
                        str(row.get("status") or row.get("strategy") or ""),
                        str(row.get("output_path") or ""),
                    )

    ledger = _load_json(workspace / ".auditooor" / "commit_lifecycle_ledger.json")
    if isinstance(ledger, dict):
        for row in ledger.get("target_rows") or []:
            if not isinstance(row, dict):
                continue
            _record(
                str(row.get("owner_repo") or ""),
                str(row.get("status") or row.get("strategy") or ""),
                str(row.get("output_path") or ""),
            )

    return out


def _manifest_logged_unresolved_roots(workspace: Path) -> set[str]:
    """Set of in_scope roots the manifest already logged as unresolved."""
    logged: set[str] = set()
    man = _latest_manifest(workspace)
    if man is None:
        return logged
    payload = _load_json(man)
    if not isinstance(payload, dict):
        return logged
    for entry in payload.get("unresolved_inscope_roots") or []:
        if isinstance(entry, dict) and entry.get("root"):
            logged.add(str(entry["root"]))
    for row in payload.get("rows") or []:
        if (
            isinstance(row, dict)
            and row.get("status") == "skipped_unresolved_upstream"
            and row.get("inscope_root")
        ):
            logged.add(str(row["inscope_root"]))
    return logged


def evaluate(workspace: Path) -> dict[str, Any]:
    """Compute the coverage verdict for a workspace. Pure (no stdout)."""
    driver = _load_driver()
    scope_path = workspace / "scope.json"

    # Fail-safe: no scope.json / no in_scope -> n/a pass (never block).
    if not scope_path.is_file():
        return {
            "verdict": "pass-multi-repo-mining-coverage",
            "reason": "no in_scope manifest (n/a)",
            "na": True,
            "required": [],
            "covered": [],
            "skip_logged": [],
            "uncovered": [],
            "unresolved_roots": [],
            "unlogged_unresolved_roots": [],
        }

    resolved = driver.inscope_owner_repos(workspace)
    inscope_repos = sorted(resolved["owner_repos"].keys())
    unresolved_roots = list(resolved["unresolved_roots"])

    if not inscope_repos and not unresolved_roots:
        return {
            "verdict": "pass-multi-repo-mining-coverage",
            "reason": "no in_scope manifest (n/a)",
            "na": True,
            "required": [],
            "covered": [],
            "skip_logged": [],
            "uncovered": [],
            "unresolved_roots": [],
            "unlogged_unresolved_roots": [],
        }

    statuses = _manifest_repo_statuses(workspace)
    logged_unresolved = _manifest_logged_unresolved_roots(workspace)

    covered: list[str] = []
    skip_logged: list[str] = []
    uncovered: list[str] = []
    for owner_repo in inscope_repos:
        entry = statuses.get(owner_repo)
        if entry and entry.get("covered"):
            covered.append(owner_repo)
        elif entry and entry.get("skip_logged"):
            skip_logged.append(owner_repo)
        else:
            uncovered.append(owner_repo)

    # An unresolved root is acceptable only if it was explicitly logged.
    unlogged_unresolved: list[dict[str, str]] = [
        ur
        for ur in unresolved_roots
        if str(ur.get("root") or "") not in logged_unresolved
    ]

    result: dict[str, Any] = {
        "required": inscope_repos,
        "covered": sorted(covered),
        "skip_logged": sorted(skip_logged),
        "uncovered": sorted(uncovered),
        "unresolved_roots": unresolved_roots,
        "unlogged_unresolved_roots": unlogged_unresolved,
        "na": False,
    }

    if uncovered or unlogged_unresolved:
        parts = []
        if uncovered:
            parts.append("fail-multi-repo-mining-coverage: " + ", ".join(sorted(uncovered)))
        else:
            parts.append("fail-multi-repo-mining-coverage:")
        if unlogged_unresolved:
            parts.append(
                "unlogged-unresolved-roots: "
                + ", ".join(str(ur.get("root") or "") for ur in unlogged_unresolved)
            )
        result["verdict"] = "fail-multi-repo-mining-coverage"
        result["reason"] = " | ".join(parts)
        return result

    # No uncovered repos, no unlogged unresolved roots. WARN if any only
    # SKIP-LOGGED, or any unresolved root is present (but logged).
    if skip_logged or unresolved_roots:
        degraded = sorted(set(skip_logged) | {
            str(ur.get("root") or "") for ur in unresolved_roots
        })
        result["verdict"] = "warn-multi-repo-mining-coverage"
        result["reason"] = (
            "warn-multi-repo-mining-coverage: " + ", ".join(d for d in degraded if d)
        )
        return result

    result["verdict"] = "pass-multi-repo-mining-coverage"
    result["reason"] = (
        f"all {len(inscope_repos)} in-scope owner/repo(s) covered: "
        + ", ".join(inscope_repos)
    )
    return result


def _write_sidecar(workspace: Path, result: dict[str, Any]) -> Path:
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.multi_repo_mining_coverage.v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "workspace": str(workspace),
        **result,
    }
    out_path = out_dir / "multi_repo_mining_coverage.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true", help="emit the full verdict as JSON")
    ap.add_argument("--strict", action="store_true", help="L37 strict path (fail stays rc 1)")
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(
            f"[multi-repo-mining-coverage] ERR workspace not found: {workspace}",
            file=sys.stderr,
        )
        return 2

    result = evaluate(workspace)
    try:
        _write_sidecar(workspace, result)
    except OSError:
        pass

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))

    verdict = str(result.get("verdict") or "")
    is_fail = verdict.startswith("fail-")
    # Final, machine-parseable verdict line is ALWAYS the last stdout line.
    print(result.get("reason") or verdict)

    # rc: 0 for pass/warn, 1 for fail (strict and non-strict both fail-closed on
    # a genuine uncovered repo; a logged skip / warn never blocks).
    return 1 if is_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
