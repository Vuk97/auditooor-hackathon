#!/usr/bin/env python3
# r36-rebuttal: CAPABILITY-GAP-CLOSURE-2026-05-26 lane (X4 closure)
"""mcp-callable-health-check.py - exercise every vault_* callable with known-good args.

Closes capability gap X4 (codified 2026-05-26 docs/CAPABILITY_GAPS_2026-05-26_ITER_FROM_CHAT.md):
hunt-side MCP callables silently return empty when args incomplete; orchestrator
misreads "0 items" as "callable is empty/broken" when the real cause is just
missing required kwargs.

This tool reads tools/mcp-callable-args-manifest.json (from X2) and exercises
every vault_* callable with sensible defaults: for required `corpus_dir`,
walks audit/corpus_tags/tags/ subdirs; for required `workspace_path`, uses the
auditooor-mcp workspace itself. Reports {callable -> records_returned,
degraded_reason} so the orchestrator sees true health, not arg-shape FPs.

USAGE
    python3 tools/mcp-callable-health-check.py
        # Run all callables, JSON summary to stdout

    python3 tools/mcp-callable-health-check.py --only vault_post_mortem_corpus
        # Run one callable

    python3 tools/mcp-callable-health-check.py --required-only
        # Only exercise callables with required kwargs (the 14 from manifest)

    python3 tools/mcp-callable-health-check.py --out reports/mcp_health_2026-05-26.json
        # Persist report
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOL_NAME = "mcp-callable-health-check"
TOOL_VERSION = "1.0.0"

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"
MANIFEST = REPO_ROOT / "reference" / "mcp_callable_args_manifest.json"


def default_corpus_dirs() -> List[str]:
    """Walk audit/corpus_tags/tags/ for non-empty subdirs to try as corpus_dir."""
    base = REPO_ROOT / "audit" / "corpus_tags" / "tags"
    if not base.is_dir():
        return []
    out = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and any(d.iterdir()):
            out.append(f"audit/corpus_tags/tags/{d.name}")
    return out


def best_args_for(callable_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a list of arg-dicts to try for a callable. Returns a list because
    some callables benefit from being tried with multiple defaults (e.g.
    corpus_dir across different subdirs)."""
    required = set(callable_info.get("required_kwargs", []))
    optional = set(callable_info.get("optional_kwargs", []))
    base: Dict[str, Any] = {}
    # Default common optional fields
    if "limit" in optional:
        base["limit"] = 3
    if "workspace_path" in (required | optional):
        base["workspace_path"] = str(REPO_ROOT)
    if "draft_path" in required:
        # Pick any existing draft; if none, skip exercise
        drafts = list((REPO_ROOT / "obsidian-vault" / "anti-patterns").glob("*.md"))[:1]
        if drafts:
            base["draft_path"] = str(drafts[0])
    if "report_path" in required:
        # Pick any json report
        reports = list(REPO_ROOT.glob("reports/*.json"))[:1]
        if reports:
            base["report_path"] = str(reports[0])
    if "exec_record_path" in required:
        execs = list(REPO_ROOT.glob("reports/v3_iter_*/lane_*/results.md"))[:1]
        if execs:
            base["exec_record_path"] = str(execs[0])
    if "identifier" in required:
        base["identifier"] = "CVE-2024-12345"
    if "attack_class" in required:
        base["attack_class"] = "reentrancy"
    # For corpus_dir-required callables, return one variant per available corpus
    if "corpus_dir" in required:
        variants = []
        for cd in default_corpus_dirs()[:3]:  # cap to 3 to keep run-time bounded
            v = dict(base)
            v["corpus_dir"] = cd
            variants.append(v)
        if variants:
            return variants
        return [base]  # will likely degrade but worth recording
    return [base]


# LLM-backed callables are legitimately slow (30-90s); a 15s default false-flags
# them as ERROR. Per-callable timeout overrides keep the audit honest.
SLOW_CALLABLES = {
    "vault_hackerman_chain_candidates": 90,
    "vault_hackerman_detector_relationships": 90,
    "vault_hackerman_exploit_predicates": 90,
    "vault_hackerman_go_cosmos_inventory": 90,
    "vault_hackerman_novel_vector_context": 90,
    "vault_global_chain_template_match": 60,
    "vault_chained_attack_plan_context": 60,
}


def call_mcp(callable_name: str, args: Dict[str, Any], timeout_s: int = 15) -> Dict[str, Any]:
    """Invoke vault-mcp-server.py via subprocess and return the response."""
    cmd = [
        sys.executable, str(MCP_SERVER),
        "--call", callable_name,
        "--args", json.dumps(args),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        if proc.returncode != 0:
            return {"_health_error": "non-zero-exit", "stderr": proc.stderr[:500]}
        return json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return {"_health_error": "timeout", "timeout_s": timeout_s}
    except json.JSONDecodeError as e:
        return {"_health_error": "stdout-not-json", "stdout_head": proc.stdout[:200]}
    except Exception as e:
        return {"_health_error": str(e)[:200]}


def count_records(response: Dict[str, Any]) -> int:
    """Count records in a vault response - tries multiple shape conventions."""
    if not isinstance(response, dict):
        return 0
    if response.get("_health_error"):
        return -1
    for key in ("records_count", "records_returned", "invariants_in_corpus",
                "anti_patterns_count", "total_invariants_matched"):
        v = response.get(key)
        if isinstance(v, int) and v > 0:
            return v
    for key in ("records", "items", "invariants", "anti_patterns", "rows",
                "post_mortems", "hits", "candidates"):
        v = response.get(key)
        if isinstance(v, list):
            return len(v)
    return 0


def health_check_one(callable_info: Dict[str, Any]) -> Dict[str, Any]:
    name = callable_info["name"]
    variants = best_args_for(callable_info)
    best_count = -1
    best_args = None
    best_degraded = None
    call_timeout = SLOW_CALLABLES.get(name, 15)
    for variant in variants:
        resp = call_mcp(name, variant, timeout_s=call_timeout)
        n = count_records(resp)
        deg = resp.get("degraded") if isinstance(resp, dict) else None
        reason = resp.get("reason") if isinstance(resp, dict) else None
        if n > best_count:
            best_count = n
            best_args = variant
            best_degraded = (deg, reason)
        if n > 0 and not deg:
            break  # found a working call
    status = "ok"
    if best_count == -1:
        status = "ERROR"
    elif best_count == 0:
        status = "EMPTY"
    elif best_degraded and best_degraded[0]:
        status = "DEGRADED"
    return {
        "name": name,
        "status": status,
        "records_returned": max(best_count, 0),
        "args_used": best_args,
        "degraded_reason": best_degraded[1] if best_degraded else None,
        "variants_tried": len(variants),
    }


def main() -> int:
    p = argparse.ArgumentParser(prog=TOOL_NAME)
    p.add_argument("--only", help="Only test this callable")
    p.add_argument("--required-only", action="store_true", help="Only test callables with required kwargs")
    p.add_argument("--out", help="Write JSON report to file")
    p.add_argument("--timeout", type=int, default=15, help="Per-call timeout seconds")
    args = p.parse_args()

    if not MANIFEST.is_file():
        print(f"error: manifest not found at {MANIFEST}; run tools/mcp-callable-args-manifest.py first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST.read_text())
    callables = manifest["callables"]

    if args.only:
        callables = [c for c in callables if c["name"] == args.only]
        if not callables:
            print(f"callable not found: {args.only}", file=sys.stderr)
            return 1
    elif args.required_only:
        callables = [c for c in callables if c["required_kwargs"]]

    results = []
    counts = {"ok": 0, "EMPTY": 0, "DEGRADED": 0, "ERROR": 0}
    for c in callables:
        r = health_check_one(c)
        results.append(r)
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        print(f"  {r['name']:50s} status={r['status']:9s} records={r['records_returned']:4d}", file=sys.stderr)

    report = {
        "schema": "auditooor.mcp_callable_health.v1",
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "callable_count": len(results),
        "counts": counts,
        "results": results,
    }
    out_json = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out_json + "\n", encoding="utf-8")
        print(f"\nwrote report to {args.out}", file=sys.stderr)
    else:
        print(out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
