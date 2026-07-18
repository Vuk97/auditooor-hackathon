#!/usr/bin/env python3
"""hackerman-wave1-shipment-receipt.py — immutable Wave-1 close-state envelope.

Wave-1 hackerman capability lift (PR #726). Captures the immutable shipment
state at Wave-1 close into a single canonical JSON envelope:

  - PR #726 commit count (HEAD vs base branch)
  - HEAD commit SHA
  - corpus baseline SHA (from audit/wave1_snapshots/baseline_freeze/*.json)
  - total records + tier distribution (from the baseline freeze)
  - Wave-2 readiness verdict
  - all `make hackerman-*` target names (from `make hackerman-help-json`)
  - vault_* MCP callables enumerated from `tools/vault-mcp-server.py --help`
  - HACKERMAN*.md doc inventory under docs/

Emits canonical envelope `auditooor.hackerman_wave1_shipment_receipt.v1` to
audit/wave1_snapshots/shipment_receipt/<date>.json by default.

Usage:
    python3 tools/hackerman-wave1-shipment-receipt.py
    python3 tools/hackerman-wave1-shipment-receipt.py --json
    python3 tools/hackerman-wave1-shipment-receipt.py \
        --baseline-path audit/wave1_snapshots/baseline_freeze/2026-05-16-wave1-final.json \
        --out audit/wave1_snapshots/shipment_receipt/2026-05-16.json

PR #726 / Wave-1 hackerman-capability-lift.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent

SCHEMA = "auditooor.hackerman_wave1_shipment_receipt.v1"

DEFAULT_BASE_BRANCH = "origin/main"
DEFAULT_BASELINE_GLOB = "audit/wave1_snapshots/baseline_freeze/*.json"
DEFAULT_OUT_TEMPLATE = "audit/wave1_snapshots/shipment_receipt/{date}.json"
DEFAULT_DOCS_GLOB = "docs/HACKERMAN*.md"

EXPECTED_TARGET_PREFIX = "hackerman-"


def _run(cmd: list[str], cwd: pathlib.Path) -> tuple[int, str, str]:
    """Run a subprocess and capture rc/stdout/stderr; never raises."""
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


def collect_git_state(
    repo: pathlib.Path,
    base_branch: str,
) -> dict[str, Any]:
    """Capture HEAD SHA, branch, and commit-count vs base_branch."""
    out: dict[str, Any] = {
        "head_sha": None,
        "branch": None,
        "base_branch": base_branch,
        "commit_count_vs_base": None,
        "errors": [],
    }
    rc, so, se = _run(["git", "rev-parse", "HEAD"], repo)
    if rc == 0:
        out["head_sha"] = so.strip()
    else:
        out["errors"].append(f"rev-parse HEAD: {se.strip()}")

    rc, so, se = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo)
    if rc == 0:
        out["branch"] = so.strip()
    else:
        out["errors"].append(f"rev-parse --abbrev-ref: {se.strip()}")

    rc, so, se = _run(["git", "rev-list", "--count", f"{base_branch}..HEAD"], repo)
    if rc == 0:
        try:
            out["commit_count_vs_base"] = int(so.strip())
        except ValueError:
            out["errors"].append(f"rev-list count parse: {so!r}")
    else:
        # Fallback: just count HEAD commits (best effort)
        out["errors"].append(f"rev-list count vs {base_branch}: {se.strip()}")
    return out


def collect_baseline(
    repo: pathlib.Path,
    baseline_path: pathlib.Path | None,
) -> dict[str, Any]:
    """Load the Wave-1 baseline freeze snapshot (corpus SHA + tier distribution)."""
    out: dict[str, Any] = {
        "baseline_path": None,
        "baseline_label": None,
        "corpus_sha256": None,
        "input_count": None,
        "total_records": None,
        "tier_distribution": {},
        "subtree_record_counts": {},
        "errors": [],
    }
    chosen: pathlib.Path | None = baseline_path
    if chosen is None:
        candidates = sorted(repo.glob(DEFAULT_BASELINE_GLOB))
        if candidates:
            # pick the lexicographically-last (typically the most recent dated)
            chosen = candidates[-1]
    if chosen is None or not chosen.is_file():
        out["errors"].append(
            f"baseline freeze snapshot not found (path={chosen})"
        )
        return out
    try:
        data = json.loads(chosen.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        out["errors"].append(f"baseline read/parse: {type(exc).__name__}: {exc}")
        return out

    out["baseline_path"] = str(chosen.relative_to(repo)) if chosen.is_relative_to(repo) else str(chosen)
    out["baseline_label"] = data.get("baseline_label")
    out["corpus_sha256"] = data.get("corpus_sha256")
    out["input_count"] = data.get("input_count")
    stats = data.get("stats") or {}
    out["total_records"] = stats.get("total_records")
    out["tier_distribution"] = dict(stats.get("tier_distribution") or {})
    out["subtree_record_counts"] = dict(stats.get("subtree_record_counts") or {})
    return out


def collect_hackerman_targets(repo: pathlib.Path) -> dict[str, Any]:
    """Invoke `make hackerman-help-json` and pull target names."""
    out: dict[str, Any] = {
        "targets": [],
        "target_count": 0,
        "schema": None,
        "errors": [],
    }
    rc, so, se = _run(["make", "--no-print-directory", "hackerman-help-json"], repo)
    if rc != 0:
        out["errors"].append(f"make hackerman-help-json rc={rc}: {se.strip()[:200]}")
        return out
    try:
        data = json.loads(so)
    except json.JSONDecodeError as exc:
        out["errors"].append(f"help-json parse: {exc}")
        return out
    out["schema"] = data.get("schema")
    targets = data.get("targets") or []
    names = sorted({(t.get("target") or "").strip() for t in targets if t.get("target")})
    out["targets"] = [n for n in names if n]
    out["target_count"] = len(out["targets"])
    # also surface what help-json itself reported as target_count (sanity)
    out["target_count_reported"] = data.get("target_count")
    return out


VAULT_CALLABLE_RE = re.compile(r"vault_[a-z][a-z0-9_]*")


def collect_vault_callables(repo: pathlib.Path) -> dict[str, Any]:
    """Enumerate vault_* callables from `vault-mcp-server.py --help`."""
    out: dict[str, Any] = {
        "callables": [],
        "callable_count": 0,
        "errors": [],
    }
    server = repo / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        out["errors"].append(f"vault-mcp-server.py missing at {server}")
        return out
    rc, so, se = _run(["python3", str(server), "--help"], repo)
    if rc != 0 and not so:
        out["errors"].append(f"vault-mcp-server --help rc={rc}: {se.strip()[:200]}")
        return out
    blob = so + "\n" + se
    matches = sorted(set(VAULT_CALLABLE_RE.findall(blob)))
    out["callables"] = matches
    out["callable_count"] = len(matches)
    return out


def collect_hackerman_docs(repo: pathlib.Path, doc_glob: str) -> dict[str, Any]:
    """Enumerate HACKERMAN*.md docs under docs/."""
    docs = sorted(repo.glob(doc_glob))
    rel = [str(p.relative_to(repo)) for p in docs if p.is_file()]
    return {
        "doc_glob": doc_glob,
        "docs": rel,
        "doc_count": len(rel),
    }


def derive_wave2_readiness(
    git_state: dict[str, Any],
    baseline: dict[str, Any],
    targets: dict[str, Any],
    callables: dict[str, Any],
    docs: dict[str, Any],
) -> dict[str, Any]:
    """Apply a small rubric to decide Wave-2 readiness verdict.

    Required for `ready`:
      - HEAD SHA present
      - corpus_sha256 present
      - total_records > 0
      - at least 1 hackerman-* target
      - at least 1 vault_* callable
      - at least 1 HACKERMAN doc
      - no fatal errors in any collector

    Otherwise `not-ready` with reasons.
    """
    reasons: list[str] = []
    if not git_state.get("head_sha"):
        reasons.append("missing HEAD SHA")
    if not baseline.get("corpus_sha256"):
        reasons.append("missing corpus_sha256")
    if not baseline.get("total_records"):
        reasons.append("missing total_records")
    if not targets.get("target_count"):
        reasons.append("no hackerman-* targets enumerated")
    if not callables.get("callable_count"):
        reasons.append("no vault_* callables enumerated")
    if not docs.get("doc_count"):
        reasons.append("no HACKERMAN docs found")
    for col_name, col in (
        ("git", git_state), ("baseline", baseline),
        ("targets", targets), ("callables", callables),
    ):
        if col.get("errors"):
            reasons.append(f"{col_name} errors: {len(col['errors'])}")

    verdict = "ready" if not reasons else "not-ready"
    return {
        "verdict": verdict,
        "reasons": reasons,
    }


def build_envelope(
    repo: pathlib.Path,
    base_branch: str,
    baseline_path: pathlib.Path | None,
    doc_glob: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if generated_at is None:
        generated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    git_state = collect_git_state(repo, base_branch)
    baseline = collect_baseline(repo, baseline_path)
    targets = collect_hackerman_targets(repo)
    callables = collect_vault_callables(repo)
    docs = collect_hackerman_docs(repo, doc_glob)
    readiness = derive_wave2_readiness(git_state, baseline, targets, callables, docs)

    envelope: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "repo_root": str(repo),
        "pr": {
            "number": 726,
            "branch": git_state.get("branch"),
            "base_branch": base_branch,
            "head_sha": git_state.get("head_sha"),
            "commit_count_vs_base": git_state.get("commit_count_vs_base"),
        },
        "corpus_baseline": {
            "path": baseline.get("baseline_path"),
            "label": baseline.get("baseline_label"),
            "corpus_sha256": baseline.get("corpus_sha256"),
            "input_count": baseline.get("input_count"),
            "total_records": baseline.get("total_records"),
            "tier_distribution": baseline.get("tier_distribution"),
            "subtree_record_counts": baseline.get("subtree_record_counts"),
        },
        "hackerman_targets": {
            "count": targets.get("target_count"),
            "count_reported_by_help": targets.get("target_count_reported"),
            "names": targets.get("targets"),
            "help_schema": targets.get("schema"),
        },
        "vault_callables": {
            "count": callables.get("callable_count"),
            "names": callables.get("callables"),
        },
        "hackerman_docs": {
            "glob": docs.get("doc_glob"),
            "count": docs.get("doc_count"),
            "names": docs.get("docs"),
        },
        "wave2_readiness": readiness,
        "collector_errors": {
            "git": git_state.get("errors"),
            "baseline": baseline.get("errors"),
            "targets": targets.get("errors"),
            "callables": callables.get("errors"),
        },
    }
    return envelope


def emit(envelope: dict[str, Any], out_path: pathlib.Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Wave-1 shipment receipt envelope.")
    ap.add_argument("--root", default=str(REPO), help="Repo root (default: auto).")
    ap.add_argument("--base-branch", default=DEFAULT_BASE_BRANCH,
                    help="Base ref for commit-count-vs-base (default origin/main).")
    ap.add_argument("--baseline-path", default=None,
                    help="Path to baseline freeze snapshot JSON. Defaults to "
                         "the lexicographically-last file matching "
                         f"{DEFAULT_BASELINE_GLOB}.")
    ap.add_argument("--doc-glob", default=DEFAULT_DOCS_GLOB,
                    help="Glob for HACKERMAN docs.")
    ap.add_argument("--out", default=None,
                    help="Output JSON path. Defaults to "
                         f"{DEFAULT_OUT_TEMPLATE.format(date='<utc-date>')}.")
    ap.add_argument("--generated-at", default=None,
                    help="Pin envelope timestamp (reproducible builds).")
    ap.add_argument("--json", action="store_true",
                    help="Print envelope JSON to stdout (in addition to writing --out).")
    ap.add_argument("--no-write", action="store_true",
                    help="Skip writing to --out; only print to stdout.")
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 if wave2_readiness.verdict != 'ready'.")
    args = ap.parse_args(argv)

    repo = pathlib.Path(args.root).resolve()
    baseline_path = pathlib.Path(args.baseline_path).resolve() if args.baseline_path else None
    envelope = build_envelope(
        repo=repo,
        base_branch=args.base_branch,
        baseline_path=baseline_path,
        doc_glob=args.doc_glob,
        generated_at=args.generated_at,
    )

    if not args.no_write:
        if args.out:
            out_path = pathlib.Path(args.out)
        else:
            date_part = envelope["generated_at"][:10]
            out_path = repo / DEFAULT_OUT_TEMPLATE.format(date=date_part)
        if not out_path.is_absolute():
            out_path = repo / out_path
        emit(envelope, out_path)
        sys.stdout.write(
            f"hackerman-wave1-shipment-receipt: wrote {out_path}\n"
            f"  schema={envelope['schema']}\n"
            f"  head_sha={envelope['pr']['head_sha']}\n"
            f"  commit_count_vs_base={envelope['pr']['commit_count_vs_base']}\n"
            f"  corpus_sha256={envelope['corpus_baseline']['corpus_sha256']}\n"
            f"  total_records={envelope['corpus_baseline']['total_records']}\n"
            f"  hackerman_targets={envelope['hackerman_targets']['count']}\n"
            f"  vault_callables={envelope['vault_callables']['count']}\n"
            f"  hackerman_docs={envelope['hackerman_docs']['count']}\n"
            f"  wave2_readiness={envelope['wave2_readiness']['verdict']}\n"
        )

    if args.json:
        json.dump(envelope, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")

    if args.strict and envelope["wave2_readiness"]["verdict"] != "ready":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
