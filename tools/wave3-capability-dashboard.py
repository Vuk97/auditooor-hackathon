#!/usr/bin/env python3
"""Wave-3 capability dashboard.

Single-command surface of auditooor's current capability state across all
axes.  Designed to answer the operator's question "where do we stand?"
without re-deriving from scattered docs.

Sections:

* A. Detector inventory by language / tier / source.
* B. MCP callable inventory + test coverage.
* C. Per-workspace capability state (morpho-midnight / hyperbridge / near / dydx / zebra by default).
* D. Cross-protocol pattern transfer summary (best-effort doc parse).
* E. Wave-2 close criteria (PR-A + PR-B; tolerates missing readiness tools).
* F. Wave-3 lane progress (best-effort lane-setup-spec parse).
* G. Outstanding capability gaps (Wave-3 follow-ups; best-effort parse).
* H. Test failure status (bounded fast subset; opt-in deep mode).

Output schema: ``auditooor.wave3_capability_dashboard.v1``.

Read-only.  Tolerates missing input docs / missing readiness tools via
SKIP verdicts with diagnostics so the dashboard renders cleanly during
early Wave-3 when not all artifacts have landed yet.

CLI:

    python3 tools/wave3-capability-dashboard.py \
        --workspace /Users/wolf/auditooor-702-full \
        --include-workspaces morpho-midnight,hyperbridge,near,dydx,zebra \
        --markdown

Exit codes:

    0 - dashboard rendered (including SKIP verdicts)
    1 - tooling error (unreadable workspace, etc.)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA_ID = "auditooor.wave3_capability_dashboard.v1"

DEFAULT_WORKSPACES = ("morpho-midnight", "hyperbridge", "near", "dydx", "zebra")
DEFAULT_AUDITS_ROOT = Path("/Users/wolf/audits")

# Wave-2-A close-readiness lives in PR-A line of work; PR-B equivalent
# is ``tools/wave2-b-close-readiness.py``.  The dashboard tolerates
# either being absent.
WAVE2_A_TOOL_RELPATH = Path("tools/wave2-a-close-readiness.py")
WAVE2_B_TOOL_RELPATH = Path("tools/wave2-b-close-readiness.py")

# Optional Wave-3 docs.  Missing = SKIP, not crash.
WAVE3_LANE_SETUP_SPEC = Path("docs/WAVE3_LANE_SETUP_SPEC_2026-05-16.md")
WAVE3_FOLLOWUPS_DOC = Path("docs/WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md")
WAVE3_CROSS_PROTOCOL_DOC = Path("docs/WAVE3_CROSS_PROTOCOL_PATTERN_TRANSFER_2026-05-16.md")

CORPUS_TAGS_RELPATH = Path("audit/corpus_tags/tags")
DETECTORS_RELPATH = Path("detectors")
MCP_SERVER_RELPATH = Path("tools/vault-mcp-server.py")
TESTS_DIR_RELPATH = Path("tools/tests")

# Language detection by detector subdir name.
LANG_BY_SUBDIR = {
    "go_wave1": "go",
    "rust_wave1": "rust",
    "rust_wave2": "rust",
    "cairo_wave1": "cairo",
    "move_wave2": "move",
    "vyper_wave2": "vyper",
    "python_wave1": "python",
    "noir_wave1": "noir",
    "halo2_wave1": "halo2",
    "plonky2_wave1": "plonky2",
    "plonky3_wave1": "plonky3",
    "circom_wave1": "circom",
    "risc0_wave1": "risc0",
    "bellperson_wave1": "bellperson",
    "gnark_wave1": "gnark",
    "pil_wave1": "pil",
    "arkworks_wave1": "arkworks",
}

# Tier-by-subdir mapping (best-effort, structural).
TIER_BY_SUBDIR_PREFIX = {
    "wave": "wave",
    "go_wave1": "wave1",
    "rust_wave1": "wave1",
    "rust_wave2": "wave2",
    "cairo_wave1": "wave1",
    "move_wave2": "wave2",
    "vyper_wave2": "wave2",
}

# MCP callable count "soft" target (Wave-2 aimed at 66; Wave-3 may grow).
MCP_CALLABLE_SOFT_TARGET = 66

# Test subset for "fast" mode (--include-test-failures).  Bounded
# explicitly so the dashboard never exceeds ~30 s on the focused
# regression suite operator runs before every commit.
FAST_TEST_MODULES = (
    "tools.tests.test_memory_deep_crawler",
    "tools.tests.test_pr_hygiene_check",
    "tools.tests.test_workpack_validator",
    "tools.tests.test_memory_gap_analyzer",
    "tools.tests.test_memory_commits_emitter",
    "tools.tests.test_makefile_vault_routing",
    "tools.tests.test_obsidian_vault_sync",
    "tools.tests.test_obsidian_vault_sync_workspaces",
)


# --------------------------------------------------------------------- #
# Section A: detector inventory
# --------------------------------------------------------------------- #

def section_a_detector_inventory(workspace: Path) -> dict[str, Any]:
    """Inventory detector counts by language / tier / source.

    Sources:

    * ``audit/corpus_tags/tags/dsl_pattern_*.yaml`` (DSL patterns).
    * ``detectors/<lang_wave>/*.py`` (AbstractDetector-style per-lang).
    * ``detectors/wave<N>/*.py`` (Solidity Slither-style waves).
    """
    tags_dir = workspace / CORPUS_TAGS_RELPATH
    detectors_dir = workspace / DETECTORS_RELPATH

    summary: dict[str, Any] = {
        "status": "OK",
        "metrics": {
            "total_detectors": 0,
            "dsl_pattern_yaml_count": 0,
            "abstract_detector_py_count": 0,
            "by_language": {},
            "by_tier": {},
            "by_source": {},
        },
        "source_files": [],
        "diagnostics": [],
    }

    by_language: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_source: dict[str, int] = {}

    # --- DSL patterns (corpus tags) ---
    if tags_dir.is_dir():
        dsl_count = 0
        for entry in tags_dir.iterdir():
            if entry.is_file() and entry.name.startswith("dsl_pattern_") and entry.name.endswith(".yaml"):
                dsl_count += 1
        summary["metrics"]["dsl_pattern_yaml_count"] = dsl_count
        by_source["dsl_pattern_yaml"] = dsl_count
        # DSL patterns are language-agnostic / multi-language by nature.
        by_language["dsl_pattern_corpus"] = dsl_count
        by_tier["corpus"] = dsl_count
        summary["source_files"].append(str(tags_dir))
    else:
        summary["diagnostics"].append(f"tags_dir_missing:{tags_dir}")

    # --- AbstractDetector python files ---
    if detectors_dir.is_dir():
        abstract_count = 0
        for sub in sorted(detectors_dir.iterdir()):
            if not sub.is_dir() or sub.name.startswith("_"):
                continue
            try:
                py_files = [
                    p for p in sub.iterdir()
                    if p.is_file() and p.suffix == ".py" and not p.name.startswith("_")
                ]
            except OSError:
                py_files = []
            if not py_files:
                continue
            n = len(py_files)
            abstract_count += n
            lang = LANG_BY_SUBDIR.get(sub.name, "solidity_or_other")
            by_language[lang] = by_language.get(lang, 0) + n
            tier_key = sub.name
            by_tier[tier_key] = by_tier.get(tier_key, 0) + n
        summary["metrics"]["abstract_detector_py_count"] = abstract_count
        by_source["abstract_detector_py"] = abstract_count
        summary["source_files"].append(str(detectors_dir))
    else:
        summary["diagnostics"].append(f"detectors_dir_missing:{detectors_dir}")

    summary["metrics"]["total_detectors"] = (
        summary["metrics"]["dsl_pattern_yaml_count"]
        + summary["metrics"]["abstract_detector_py_count"]
    )
    summary["metrics"]["by_language"] = by_language
    summary["metrics"]["by_tier"] = by_tier
    summary["metrics"]["by_source"] = by_source
    summary["summary"] = (
        f"{summary['metrics']['total_detectors']} detectors "
        f"({summary['metrics']['dsl_pattern_yaml_count']} DSL patterns + "
        f"{summary['metrics']['abstract_detector_py_count']} AbstractDetector py files)"
    )
    return summary


# --------------------------------------------------------------------- #
# Section B: MCP callable inventory
# --------------------------------------------------------------------- #

_SCHEMA_NAME_RE = re.compile(r'^\s*"name":\s*"(vault_[a-z0-9_]+)"', re.MULTILINE)
_METHOD_DEF_RE = re.compile(r"^    def (vault_[a-z0-9_]+)\s*\(", re.MULTILINE)
_DISPATCH_RE = re.compile(r'^\s+if name == "(vault_[a-z0-9_]+)":', re.MULTILINE)


def section_b_mcp_callable_inventory(workspace: Path) -> dict[str, Any]:
    """Count MCP callables and test coverage.

    Best-effort: derives the callable set from
    ``tools/vault-mcp-server.py`` directly (regex extract).  Coverage is
    the fraction of callables that have a test module in
    ``tools/tests/`` whose name longest-prefix-matches the callable.
    """
    server_path = workspace / MCP_SERVER_RELPATH
    tests_dir = workspace / TESTS_DIR_RELPATH

    summary: dict[str, Any] = {
        "status": "OK",
        "metrics": {
            "total_callables": 0,
            "test_coverage_pct": 0.0,
            "covered_callables": 0,
            "uncovered_callables": [],
            "soft_target": MCP_CALLABLE_SOFT_TARGET,
            "soft_target_met": False,
        },
        "source_files": [],
        "diagnostics": [],
    }

    if not server_path.is_file():
        summary["status"] = "SKIP"
        summary["diagnostics"].append(f"server_missing:{server_path}")
        summary["summary"] = "MCP server not found"
        return summary

    text = server_path.read_text(errors="replace")
    schema_names = set(_SCHEMA_NAME_RE.findall(text))
    method_names = set(_METHOD_DEF_RE.findall(text))
    dispatch_names = set(_DISPATCH_RE.findall(text))
    callables = sorted(schema_names | method_names | dispatch_names)
    summary["metrics"]["total_callables"] = len(callables)
    summary["source_files"].append(str(server_path))

    # Test coverage
    if tests_dir.is_dir():
        test_files = [p.name for p in tests_dir.iterdir() if p.is_file() and p.name.startswith("test_")]
        test_blob = "\n".join(test_files)
        covered: list[str] = []
        uncovered: list[str] = []
        for c in callables:
            # callable "vault_resume_context" -> test_vault_resume_context.py
            # Substring match (not word-boundary, since underscores are
            # word-chars and break the \b semantics for snake_case names).
            slug = c.replace("vault_", "")
            if c in test_blob or slug in test_blob:
                covered.append(c)
            else:
                uncovered.append(c)
        if callables:
            pct = 100.0 * len(covered) / len(callables)
        else:
            pct = 0.0
        summary["metrics"]["covered_callables"] = len(covered)
        summary["metrics"]["test_coverage_pct"] = round(pct, 1)
        summary["metrics"]["uncovered_callables"] = uncovered[:20]
        summary["source_files"].append(str(tests_dir))
    else:
        summary["diagnostics"].append(f"tests_dir_missing:{tests_dir}")

    summary["metrics"]["soft_target_met"] = (
        summary["metrics"]["total_callables"] >= MCP_CALLABLE_SOFT_TARGET
    )
    summary["summary"] = (
        f"{summary['metrics']['total_callables']} MCP callables "
        f"({summary['metrics']['covered_callables']} covered, "
        f"{summary['metrics']['test_coverage_pct']}%); "
        f"soft target {MCP_CALLABLE_SOFT_TARGET}: "
        f"{'MET' if summary['metrics']['soft_target_met'] else 'BELOW'}"
    )
    return summary


# --------------------------------------------------------------------- #
# Section C: per-workspace capability state
# --------------------------------------------------------------------- #

def _engage_report_metrics(report_path: Path) -> dict[str, Any]:
    """Pull a few headline numbers out of an engage_report.md."""
    try:
        text = report_path.read_text(errors="replace")
    except OSError:
        return {"available": False}
    m_hits = re.search(r"Total hits:\s*\*\*(\d+)\*\*", text)
    m_clusters = re.search(r"Analogical clusters:\s*(\d+)", text)
    m_detectors = re.search(r"Distinct detectors:\s*(\d+)", text)
    try:
        mtime = _dt.datetime.fromtimestamp(report_path.stat().st_mtime, _dt.timezone.utc).isoformat()
    except OSError:
        mtime = None
    return {
        "available": True,
        "path": str(report_path),
        "total_hits": int(m_hits.group(1)) if m_hits else None,
        "cluster_count": int(m_clusters.group(1)) if m_clusters else None,
        "distinct_detectors": int(m_detectors.group(1)) if m_detectors else None,
        "last_refresh": mtime,
    }


def section_c_per_workspace(workspaces: Iterable[str], audits_root: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "status": "OK",
        "metrics": {"workspaces": {}, "active_workspaces": 0, "total_tier6_seeds": 0},
        "source_files": [],
        "diagnostics": [],
    }
    active = 0
    total_tier6 = 0
    for ws in workspaces:
        ws_dir = audits_root / ws
        block: dict[str, Any] = {"present": ws_dir.is_dir()}
        if not ws_dir.is_dir():
            block["diagnostic"] = f"workspace_dir_missing:{ws_dir}"
            summary["metrics"]["workspaces"][ws] = block
            continue
        active += 1
        # engage_report.md
        engage = ws_dir / "engage_report.md"
        block["engage_report"] = _engage_report_metrics(engage)
        if engage.exists():
            summary["source_files"].append(str(engage))
        # derived_detectors/
        derived_dir = ws_dir / "derived_detectors"
        if derived_dir.is_dir():
            dd = [p for p in derived_dir.iterdir() if p.is_file() and p.suffix in {".yaml", ".yml"}]
            block["derived_detectors_count"] = len(dd)
        else:
            block["derived_detectors_count"] = 0
        # Tier-6 seeds via mining_rounds/*tier6*
        mining = ws_dir / "mining_rounds"
        tier6_rounds = 0
        if mining.is_dir():
            for sub in mining.iterdir():
                if sub.is_dir() and "tier6" in sub.name.lower():
                    tier6_rounds += 1
        block["tier6_mining_rounds"] = tier6_rounds
        total_tier6 += tier6_rounds
        # audit_pin.txt if present
        pin = ws_dir / ".auditooor" / "audit_pin.txt"
        if pin.exists():
            try:
                block["audit_pin"] = pin.read_text(errors="replace").strip()[:80]
            except OSError:
                pass
        summary["metrics"]["workspaces"][ws] = block
    summary["metrics"]["active_workspaces"] = active
    summary["metrics"]["total_tier6_seeds"] = total_tier6
    summary["summary"] = (
        f"{active}/{len(list(workspaces))} workspaces present; "
        f"{total_tier6} Tier-6 mining rounds across them"
    )
    return summary


# --------------------------------------------------------------------- #
# Section D: cross-protocol pattern transfer
# --------------------------------------------------------------------- #

def section_d_cross_protocol_transfer(workspace: Path) -> dict[str, Any]:
    """Parse WAVE3 cross-protocol transfer doc; SKIP if missing."""
    doc = workspace / WAVE3_CROSS_PROTOCOL_DOC
    if not doc.is_file():
        return {
            "status": "SKIP",
            "summary": "cross-protocol transfer doc not yet shipped",
            "metrics": {},
            "source_files": [],
            "diagnostics": [f"doc_missing:{doc}"],
        }
    text = doc.read_text(errors="replace")
    # Best-effort regex: lines starting with "- " under a heading
    # like "## Universal patterns" / "## Stack-specific patterns".
    universal = 0
    stack_specific = 0
    in_universal = False
    in_stack_specific = False
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("#") and "universal" in low:
            in_universal, in_stack_specific = True, False
            continue
        if low.startswith("#") and ("stack-specific" in low or "stack specific" in low):
            in_universal, in_stack_specific = False, True
            continue
        if low.startswith("#"):
            in_universal, in_stack_specific = False, False
            continue
        if line.strip().startswith(("- ", "* ")):
            if in_universal:
                universal += 1
            elif in_stack_specific:
                stack_specific += 1
    return {
        "status": "OK",
        "summary": f"{universal} universal + {stack_specific} stack-specific patterns",
        "metrics": {
            "universal_patterns": universal,
            "stack_specific_patterns": stack_specific,
            "total_patterns": universal + stack_specific,
        },
        "source_files": [str(doc)],
        "diagnostics": [],
    }


# --------------------------------------------------------------------- #
# Section E: Wave-2 close criteria
# --------------------------------------------------------------------- #

def _run_readiness_tool(workspace: Path, tool_relpath: Path) -> dict[str, Any]:
    tool = workspace / tool_relpath
    if not tool.is_file():
        return {"status": "SKIP", "reason": f"tool_missing:{tool}"}
    try:
        proc = subprocess.run(
            [sys.executable, str(tool), "--workspace", str(workspace), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "ERROR", "reason": f"exec_failed:{exc}"}
    out = proc.stdout.strip()
    if not out:
        return {"status": "ERROR", "reason": "empty_stdout", "stderr": proc.stderr[:200]}
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return {"status": "ERROR", "reason": f"json_decode:{exc}", "stdout_head": out[:200]}
    return {
        "status": "OK",
        "overall_status": data.get("overall_status", "UNKNOWN"),
        "criteria_count": len(data.get("criteria", []) or []),
        "raw": data,
    }


def section_e_wave2_close_criteria(workspace: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "status": "OK",
        "metrics": {"wave2_a": {}, "wave2_b": {}},
        "source_files": [],
        "diagnostics": [],
    }
    a = _run_readiness_tool(workspace, WAVE2_A_TOOL_RELPATH)
    b = _run_readiness_tool(workspace, WAVE2_B_TOOL_RELPATH)
    summary["metrics"]["wave2_a"] = a
    summary["metrics"]["wave2_b"] = b
    if (workspace / WAVE2_A_TOOL_RELPATH).is_file():
        summary["source_files"].append(str(workspace / WAVE2_A_TOOL_RELPATH))
    if (workspace / WAVE2_B_TOOL_RELPATH).is_file():
        summary["source_files"].append(str(workspace / WAVE2_B_TOOL_RELPATH))
    a_status = a.get("overall_status") or a.get("status", "SKIP")
    b_status = b.get("overall_status") or b.get("status", "SKIP")
    summary["summary"] = f"Wave-2-A:{a_status} / Wave-2-B:{b_status}"
    return summary


# --------------------------------------------------------------------- #
# Section F: Wave-3 lane progress
# --------------------------------------------------------------------- #

_LANE_ID_RE = re.compile(r"\bW3\.(\d+[A-Za-z]?)\b")


def section_f_wave3_lane_progress(workspace: Path) -> dict[str, Any]:
    spec = workspace / WAVE3_LANE_SETUP_SPEC
    if not spec.is_file():
        return {
            "status": "SKIP",
            "summary": "Wave-3 lane setup spec not yet shipped",
            "metrics": {},
            "source_files": [],
            "diagnostics": [f"doc_missing:{spec}"],
        }
    try:
        text = spec.read_text(errors="replace")
    except OSError as exc:
        return {
            "status": "ERROR",
            "summary": f"could not read lane spec ({exc})",
            "metrics": {},
            "source_files": [str(spec)],
            "diagnostics": [],
        }
    lane_ids = sorted(set(_LANE_ID_RE.findall(text)))
    # Best-effort commit-landing detection: search git log for the lane id.
    landed: dict[str, bool] = {}
    if lane_ids and shutil.which("git"):
        try:
            log = subprocess.run(
                ["git", "-C", str(workspace), "log", "--oneline", "-n", "500"],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except (subprocess.TimeoutExpired, OSError):
            log = ""
        for lid in lane_ids:
            landed[lid] = bool(re.search(rf"\bW3\.{re.escape(lid)}\b", log))
    return {
        "status": "OK",
        "summary": f"{len(lane_ids)} Wave-3 lanes declared; {sum(landed.values())} landed",
        "metrics": {
            "lanes": lane_ids,
            "landed": landed,
            "lane_count": len(lane_ids),
            "landed_count": sum(landed.values()),
        },
        "source_files": [str(spec)],
        "diagnostics": [],
    }


# --------------------------------------------------------------------- #
# Section G: outstanding capability gaps (Wave-3 follow-ups)
# --------------------------------------------------------------------- #

def section_g_wave3_followups(workspace: Path) -> dict[str, Any]:
    doc = workspace / WAVE3_FOLLOWUPS_DOC
    if not doc.is_file():
        return {
            "status": "SKIP",
            "summary": "Wave-3 follow-ups doc not yet shipped",
            "metrics": {},
            "source_files": [],
            "diagnostics": [f"doc_missing:{doc}"],
        }
    text = doc.read_text(errors="replace")
    # Count bullet items, status markers ("- [ ]" vs "- [x]").
    open_items = len(re.findall(r"^- \[ \]", text, re.MULTILINE))
    done_items = len(re.findall(r"^- \[x\]", text, re.MULTILINE, ))
    total = open_items + done_items
    return {
        "status": "OK",
        "summary": f"{open_items} open / {done_items} done / {total} total follow-ups",
        "metrics": {
            "open_followups": open_items,
            "done_followups": done_items,
            "total_followups": total,
        },
        "source_files": [str(doc)],
        "diagnostics": [],
    }


# --------------------------------------------------------------------- #
# Section H: test failure status (bounded)
# --------------------------------------------------------------------- #

def section_h_test_failures(workspace: Path, *, run_tests: bool) -> dict[str, Any]:
    if not run_tests:
        return {
            "status": "SKIP",
            "summary": "test run skipped (pass --include-test-failures to opt in)",
            "metrics": {"modules": list(FAST_TEST_MODULES), "run": False},
            "source_files": [],
            "diagnostics": [],
        }
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", *FAST_TEST_MODULES],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {
            "status": "ERROR",
            "summary": f"unittest invocation failed: {exc}",
            "metrics": {"run": True},
            "source_files": [],
            "diagnostics": [],
        }
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m_failures = re.search(r"failures=(\d+)", output)
    m_errors = re.search(r"errors=(\d+)", output)
    m_ran = re.search(r"Ran (\d+) tests", output)
    failures = int(m_failures.group(1)) if m_failures else 0
    errors = int(m_errors.group(1)) if m_errors else 0
    ran = int(m_ran.group(1)) if m_ran else 0
    ok = ("OK" in output.splitlines()[-3:] if output else False)
    return {
        "status": "OK" if (failures == 0 and errors == 0 and proc.returncode == 0) else "FAIL",
        "summary": f"{ran} tests ran; failures={failures} errors={errors} returncode={proc.returncode}",
        "metrics": {
            "ran": ran,
            "failures": failures,
            "errors": errors,
            "returncode": proc.returncode,
            "ok_line_present": ok,
            "run": True,
        },
        "source_files": list(FAST_TEST_MODULES),
        "diagnostics": [],
    }


# --------------------------------------------------------------------- #
# Top-level dashboard
# --------------------------------------------------------------------- #

def _git_head_sha(workspace: Path) -> str | None:
    if not shutil.which("git"):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    sha = proc.stdout.strip()
    return sha or None


def build_dashboard(
    workspace: Path,
    *,
    include_workspaces: Iterable[str],
    audits_root: Path,
    include_test_failures: bool,
) -> dict[str, Any]:
    sections = {
        "A_detector_inventory": section_a_detector_inventory(workspace),
        "B_mcp_callables": section_b_mcp_callable_inventory(workspace),
        "C_per_workspace": section_c_per_workspace(include_workspaces, audits_root),
        "D_cross_protocol_transfer": section_d_cross_protocol_transfer(workspace),
        "E_wave2_close_criteria": section_e_wave2_close_criteria(workspace),
        "F_wave3_lane_progress": section_f_wave3_lane_progress(workspace),
        "G_wave3_followups": section_g_wave3_followups(workspace),
        "H_test_failures": section_h_test_failures(workspace, run_tests=include_test_failures),
    }

    a = sections["A_detector_inventory"]["metrics"]
    b = sections["B_mcp_callables"]["metrics"]
    c = sections["C_per_workspace"]["metrics"]
    e = sections["E_wave2_close_criteria"]["metrics"]
    g = sections["G_wave3_followups"].get("metrics", {})

    headline = {
        "total_detectors": a.get("total_detectors", 0),
        "mcp_callables": b.get("total_callables", 0),
        "mcp_test_coverage_pct": b.get("test_coverage_pct", 0.0),
        "total_tier6_seeds": c.get("total_tier6_seeds", 0),
        "active_workspaces": c.get("active_workspaces", 0),
        "wave2_a_status": (e.get("wave2_a", {}).get("overall_status")
                           or e.get("wave2_a", {}).get("status", "SKIP")),
        "wave2_b_status": (e.get("wave2_b", {}).get("overall_status")
                           or e.get("wave2_b", {}).get("status", "SKIP")),
        "wave3_followups_remaining": g.get("open_followups", 0),
    }

    return {
        "schema_id": SCHEMA_ID,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "head_sha": _git_head_sha(workspace),
        "workspace": str(workspace),
        "included_workspaces": list(include_workspaces),
        "audits_root": str(audits_root),
        "headline_metrics": headline,
        "sections": sections,
    }


# --------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------- #

def render_markdown(dashboard: dict[str, Any]) -> str:
    h = dashboard["headline_metrics"]
    lines: list[str] = []
    lines.append("# Wave-3 capability dashboard")
    lines.append("")
    lines.append(f"- workspace: `{dashboard['workspace']}`")
    lines.append(f"- generated_at: `{dashboard['generated_at']}`")
    lines.append(f"- head_sha: `{dashboard.get('head_sha') or 'unknown'}`")
    lines.append("")
    lines.append("## Headline metrics")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    for key, val in h.items():
        lines.append(f"| {key} | {val} |")
    lines.append("")
    for section_name, sec in dashboard["sections"].items():
        lines.append(f"## {section_name}")
        lines.append("")
        lines.append(f"- status: `{sec.get('status', 'UNKNOWN')}`")
        if sec.get("summary"):
            lines.append(f"- summary: {sec['summary']}")
        diag = sec.get("diagnostics") or []
        if diag:
            lines.append(f"- diagnostics: {', '.join(diag)}")
        metrics = sec.get("metrics") or {}
        if metrics:
            lines.append("")
            lines.append("| key | value |")
            lines.append("|---|---|")
            for k, v in metrics.items():
                rendered: str
                if isinstance(v, (dict, list)):
                    rendered = f"`{json.dumps(v, sort_keys=True)[:200]}`"
                else:
                    rendered = str(v)
                lines.append(f"| {k} | {rendered} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------- #

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wave-3 capability dashboard")
    default_ws = Path(os.environ.get("AUDITOOOR_WORKSPACE", "/Users/wolf/auditooor-702-full"))
    p.add_argument("--workspace", type=Path, default=default_ws)
    p.add_argument(
        "--include-workspaces",
        type=str,
        default=",".join(DEFAULT_WORKSPACES),
        help="Comma-separated workspaces under --audits-root to summarize.",
    )
    p.add_argument("--audits-root", type=Path, default=DEFAULT_AUDITS_ROOT)
    p.add_argument("--json", action="store_true", help="Emit JSON only.")
    p.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    p.add_argument(
        "--include-test-failures",
        action="store_true",
        help="Run the bounded fast-subset unittest invocation (default off; ~30s).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = args.workspace
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1
    included = tuple(w for w in (s.strip() for s in args.include_workspaces.split(",")) if w)
    dashboard = build_dashboard(
        workspace,
        include_workspaces=included,
        audits_root=args.audits_root,
        include_test_failures=args.include_test_failures,
    )
    if args.markdown and not args.json:
        sys.stdout.write(render_markdown(dashboard))
    else:
        sys.stdout.write(json.dumps(dashboard, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
