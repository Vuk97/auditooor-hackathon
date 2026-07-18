#!/usr/bin/env python3
"""Replay local semantic fixture repairs for scanner-autonomy terminal rows."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.scanner_autonomy_semantic_repair.v1"
MANIFEST_SCHEMA = "auditooor.scanner_autonomy_semantic_repair_manifest.v1"


def _load_p1_module() -> Any:
    path = ROOT / "tools" / "p1-fixture-extractor.py"
    spec = importlib.util.spec_from_file_location("p1_fixture_extractor_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _pattern_from_row(row: dict[str, Any]) -> str:
    argv = [str(part) for part in row.get("argv") or []]
    if "--pattern" in argv:
        idx = argv.index("--pattern")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    artifact = ROOT / str(row.get("source_artifact") or "")
    manifest = _read_json(artifact)
    manifest_argv = [str(part) for part in manifest.get("argv") or []]
    if "--pattern" in manifest_argv:
        idx = manifest_argv.index("--pattern")
        if idx + 1 < len(manifest_argv):
            return manifest_argv[idx + 1]
    return ""


def _slug(pattern: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", pattern).strip("_").lower()


def _canonical_fixture_targets(pattern: str) -> dict[str, str]:
    slug = _slug(pattern)
    return {
        "canonical_vulnerable_fixture": str(ROOT / "detectors" / "test_fixtures" / f"{slug}_semantic_vulnerable.sol"),
        "canonical_clean_fixture": str(ROOT / "detectors" / "test_fixtures" / f"{slug}_semantic_clean.sol"),
    }


def _camel(raw: str, *, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", raw or "").strip()
    if not cleaned:
        cleaned = fallback
    out = "".join(part[:1].upper() + part[1:] for part in cleaned.split())
    return out if out and out[0].isalpha() else f"X{out or fallback}"


def _identifier(raw: str, *, fallback: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]+", "", raw or "")
    if not ident or not ident[0].isalpha():
        ident = fallback
    return ident


def _regex_token(source: str, name: str, *, fallback: str) -> str:
    pattern = rf"_{name}\s*=\s*re\.compile\(r[\"']([^\"']+)[\"']"
    match = re.search(pattern, source)
    if not match:
        return fallback
    regex = match.group(1)
    group = re.search(r"\(([^()]+)\)", regex)
    choices = group.group(1).split("|") if group else [regex]
    for choice in choices:
        token = re.sub(r"\\.", "", choice)
        token = re.sub(r"[^A-Za-z0-9_]+", "", token)
        if token:
            return token
    return fallback


def _detector_source(pattern: str) -> tuple[Path | None, str, str]:
    slug = _slug(pattern)
    candidates = sorted((ROOT / "detectors").glob(f"**/{slug}.py"))
    candidates.extend(path for path in sorted((ROOT / "detectors").glob(f"**/{slug}*.py")) if path not in candidates)
    for path in candidates:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        match = re.search(r"generated from skeleton `([^`]+)`", source)
        return path, source, match.group(1) if match else "unknown"
    return None, "", "missing_detector"


def _synthetic_pair_for_detector(pattern: str) -> tuple[Path | None, Path | None, dict[str, Any]]:
    detector, source, skeleton = _detector_source(pattern)
    if not detector:
        return None, None, {"synthetic_repair_status": "detector_not_found"}
    slug = _slug(pattern)
    workdir = Path("/private/tmp") / f"auditooor-semantic-repair-{slug}"
    workdir.mkdir(parents=True, exist_ok=True)
    vuln = workdir / f"{slug}_semantic_vulnerable.sol"
    clean = workdir / f"{slug}_semantic_clean.sol"
    contract = _camel(pattern, fallback="SemanticRepair")
    meta = {
        "detector_path": str(detector),
        "detector_skeleton": skeleton,
        "synthetic_vulnerable_fixture": str(vuln),
        "synthetic_clean_fixture": str(clean),
    }

    if skeleton == "name_match_missing_require":
        fn = _identifier(_regex_token(source, "FN_NAME_REGEX", fallback="setValue"), fallback="setValue")
        state = _identifier(_regex_token(source, "WRITE_VAR_REGEX", fallback="trackedValue"), fallback="trackedValue")
        guard = _identifier(_regex_token(source, "GUARD_VAR_REGEX", fallback=state), fallback=state)
        # Prefer one state variable that satisfies both write and guard regexes.
        if guard.lower() not in state.lower() and state.lower() not in guard.lower():
            state = guard
        if state.lower() == fn.lower():
            state = f"{state}State"
        vuln.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    uint256 internal {state};

    function {fn}(uint256 newValue) external {{
        {state} = newValue;
    }}
}}
""", encoding="utf-8")
        clean.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    uint256 internal {state};

    function {fn}(uint256 newValue) external {{
        require({state} <= 10000, "guard");
        {state} = newValue;
    }}
}}
""", encoding="utf-8")
        return vuln, clean, meta

    if skeleton == "name_match_missing_call":
        fn = _identifier(_regex_token(source, "FN_NAME_REGEX", fallback="targetFunction"), fallback="targetFunction")
        state = _identifier(_regex_token(source, "READ_VAR_REGEX", fallback="trackedValue"), fallback="trackedValue")
        required = _identifier(_regex_token(source, "REQUIRED_CALL_REGEX", fallback="accrue"), fallback="accrue")
        if state.lower() == fn.lower():
            state = f"{state}State"
        if required.lower() == fn.lower():
            required = f"{required}Guard"
        vuln.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    uint256 internal {state};
    uint256 internal sink;

    function {fn}() external returns (uint256) {{
        uint256 observed = {state};
        sink = observed;
        return observed;
    }}

    function {required}() internal {{
        sink = {state};
    }}
}}
""", encoding="utf-8")
        clean.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    uint256 internal {state};
    uint256 internal sink;

    function {fn}() external returns (uint256) {{
        {required}();
        uint256 observed = {state};
        sink = observed;
        return observed;
    }}

    function {required}() internal {{
        sink = {state};
    }}
}}
""", encoding="utf-8")
        return vuln, clean, meta

    if skeleton == "highlevelcall_missing_sibling":
        trigger = _identifier(_regex_token(source, "TRIGGER_SIG_REGEX", fallback="trigger"), fallback="trigger")
        sibling = _identifier(_regex_token(source, "REQUIRED_SIBLING_REGEX", fallback="accrue"), fallback="accrue")
        vuln.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISemanticTarget {{
    function {trigger}(uint256 amount) external;
    function {sibling}(uint256 amount) external;
}}

contract {contract} {{
    ISemanticTarget public target;

    constructor(ISemanticTarget target_) {{
        target = target_;
    }}

    function execute(uint256 amount) external {{
        target.{trigger}(amount);
    }}
}}
""", encoding="utf-8")
        clean.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISemanticTarget {{
    function {trigger}(uint256 amount) external;
    function {sibling}(uint256 amount) external;
}}

contract {contract} {{
    ISemanticTarget public target;

    constructor(ISemanticTarget target_) {{
        target = target_;
    }}

    function execute(uint256 amount) external {{
        target.{sibling}(amount);
        target.{trigger}(amount);
    }}
}}
""", encoding="utf-8")
        return vuln, clean, meta

    if skeleton == "paired_function_divergence":
        fwd_match = re.search(r'_FORWARD_VERB\s*=\s*r"([^"]+)"', source)
        inv_match = re.search(r'_INVERSE_VERB\s*=\s*r"([^"]+)"', source)
        forward = _identifier(fwd_match.group(1) if fwd_match else "add", fallback="add")
        inverse = _identifier(inv_match.group(1) if inv_match else "remove", fallback="remove")
        tracker = _identifier(_regex_token(source, "TRACKING_VAR_REGEX", fallback="trackingValue"), fallback="trackingValue")
        stem = "Thing"
        vuln.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    mapping(address => uint256) internal balances;
    uint256 internal {tracker};

    function {forward}{stem}(address account) external {{
        balances[account] += 1;
        {tracker} += 1;
    }}

    function {inverse}{stem}(address account) external {{
        balances[account] -= 1;
    }}
}}
""", encoding="utf-8")
        clean.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract} {{
    mapping(address => uint256) internal balances;
    uint256 internal {tracker};

    function {forward}{stem}(address account) external {{
        balances[account] += 1;
        {tracker} += 1;
    }}

    function {inverse}{stem}(address account) external {{
        balances[account] -= 1;
        {tracker} -= 1;
    }}
}}
""", encoding="utf-8")
        return vuln, clean, meta

    meta["synthetic_repair_status"] = "unsupported_detector_skeleton"
    return None, None, meta


def _row_base(row: dict[str, Any], status: str, *, pattern: str) -> dict[str, Any]:
    base = {
        "action_lane": row.get("action_lane", ""),
        "baseline_status": row.get("status", ""),
        "pattern": pattern,
        "promotion_allowed": False,
        "source_artifact": row.get("source_artifact", ""),
        "source_id": row.get("source_id", ""),
        "status": status,
        "submission_posture": "NOT_SUBMIT_READY",
        "task_id": row.get("task_id", ""),
    }
    if pattern:
        base.update(_canonical_fixture_targets(pattern))
    return base


def _review_gates(row: dict[str, Any]) -> list[str]:
    gates = [
        "human_review_confirms_synthetic_pair_matches_original_bug_family",
        "canonical_fixture_pair_is_materialized_under_detectors_test_fixtures",
        "vulnerable_fixture_produces_at_least_one_detector_hit",
        "clean_fixture_produces_zero_detector_hits",
    ]
    baseline = str(row.get("baseline_status") or "")
    if baseline == "terminal_clean_fixture_false_positive":
        gates.append("clean_fixture_or_detector_precision_guard_addresses_prior_false_positive")
    if baseline in {
        "terminal_vulnerable_fixture_no_detector_hit",
        "terminal_repaired_fixture_vulnerable_no_detector_hit",
        "terminal_generated_fixture_compile_failure",
    }:
        gates.append("vulnerable_fixture_or_detector_predicate_addresses_prior_no_hit")
    if baseline == "terminal_fixture_pair_materialized_canonical_smoke_blocked":
        gates.append("canonical_fixture_path_guard_is_not_skipping_the_materialized_pair")
    return gates


def _proof_commands(row: dict[str, Any], *, runner_python: str) -> dict[str, str]:
    pattern = str(row.get("pattern") or "")
    vuln = str(row.get("synthetic_vulnerable_fixture") or row.get("canonical_vulnerable_fixture") or "")
    clean = str(row.get("synthetic_clean_fixture") or row.get("canonical_clean_fixture") or "")
    canonical_vuln = str(row.get("canonical_vulnerable_fixture") or "")
    canonical_clean = str(row.get("canonical_clean_fixture") or "")
    runner = str(ROOT / "detectors" / "run_custom.py")
    return {
        "synthetic_vulnerable_smoke": f"{runner_python} {runner} {vuln} {pattern} --tier=ALL",
        "synthetic_clean_smoke": f"{runner_python} {runner} {clean} {pattern} --tier=ALL",
        "canonical_vulnerable_smoke": f"{runner_python} {runner} {canonical_vuln} {pattern} --tier=ALL",
        "canonical_clean_smoke": f"{runner_python} {runner} {canonical_clean} {pattern} --tier=ALL",
    }


def _manifest_for_row(row: dict[str, Any], *, runner_python: str) -> dict[str, Any]:
    status = str(row.get("status") or "")
    materialization_ready = status == "local_semantic_repair_smoke_passed"
    return {
        "schema": MANIFEST_SCHEMA,
        "source_id": row.get("source_id", ""),
        "task_id": row.get("task_id", ""),
        "pattern": row.get("pattern", ""),
        "detector_path": row.get("detector_path", ""),
        "detector_skeleton": row.get("detector_skeleton", ""),
        "baseline_status": row.get("baseline_status", ""),
        "repair_status": status,
        "materialization_ready": materialization_ready,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "source_artifact": row.get("source_artifact", ""),
        "synthetic_vulnerable_fixture": row.get("synthetic_vulnerable_fixture", ""),
        "synthetic_clean_fixture": row.get("synthetic_clean_fixture", ""),
        "canonical_vulnerable_fixture": row.get("canonical_vulnerable_fixture", ""),
        "canonical_clean_fixture": row.get("canonical_clean_fixture", ""),
        "proof_commands": _proof_commands(row, runner_python=runner_python),
        "review_gates": _review_gates(row),
        "blockers": [] if materialization_ready else list(row.get("blockers") or []),
        "next_command": (
            "materialize canonical fixture pair, rerun vulnerable/clean smoke commands, "
            "then update scanner-autonomy ledger only if vulnerable>=1 and clean==0"
            if materialization_ready
            else row.get("next_command", "repair detector predicate or fixture semantics")
        ),
    }


def _write_manifest_bundle(report: dict[str, Any], manifest_dir: Path, *, runner_python: str) -> None:
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifests: list[dict[str, Any]] = []
    for row in report.get("rows", []):
        if not isinstance(row, dict):
            continue
        manifest = _manifest_for_row(row, runner_python=runner_python)
        manifests.append(manifest)
        source_id = str(manifest.get("source_id") or "row").lower()
        slug = _slug(str(manifest.get("pattern") or source_id))
        _write_json(manifest_dir / f"{source_id}_{slug}.json", manifest)
    summary = {
        "schema": "auditooor.scanner_autonomy_semantic_repair_manifest_bundle.v1",
        "source_report": report.get("input_execution", ""),
        "manifest_count": len(manifests),
        "materialization_ready_count": sum(1 for item in manifests if item.get("materialization_ready")),
        "not_submit_ready_count": len(manifests),
        "manifest_dir": str(manifest_dir),
        "rows": [
            {
                "source_id": item.get("source_id", ""),
                "pattern": item.get("pattern", ""),
                "repair_status": item.get("repair_status", ""),
                "materialization_ready": item.get("materialization_ready", False),
                "canonical_vulnerable_fixture": item.get("canonical_vulnerable_fixture", ""),
                "canonical_clean_fixture": item.get("canonical_clean_fixture", ""),
            }
            for item in manifests
        ],
    }
    _write_json(manifest_dir / "_summary.json", summary)


def _compile_pair(p1: Any, vuln: Path, clean: Path) -> tuple[bool, str]:
    solc = shutil.which("solc")
    if not solc:
        return False, "solc_missing"
    ok_v, out_v = p1.compile_solidity(vuln, solc)
    ok_c, out_c = p1.compile_solidity(clean, solc)
    if ok_v and ok_c:
        return True, ""
    return False, f"VULN:\n{out_v[-1200:]}\nCLEAN:\n{out_c[-1200:]}"


def _smoke_pair(p1: Any, pattern: str, vuln: Path, clean: Path, *, runner_python: str) -> tuple[bool, str]:
    compiled, compile_detail = _compile_pair(p1, vuln, clean)
    if not compiled:
        return False, f"compile_failed:\n{compile_detail[-2400:]}"
    return p1.smoke_fire(
        ROOT / "detectors" / "run_custom.py",
        pattern,
        vuln,
        clean,
        tier_filter="ALL",
        python_bin=runner_python,
    )


def _synthetic_semantic_repair(p1: Any, row: dict[str, Any], *, runner_python: str) -> dict[str, Any] | None:
    pattern = _pattern_from_row(row)
    if not pattern:
        return None
    vuln, clean, meta = _synthetic_pair_for_detector(pattern)
    if not vuln or not clean:
        return None
    ok_smoke, smoke_detail = _smoke_pair(p1, pattern, vuln, clean, runner_python=runner_python)
    base = _row_base(row, "local_semantic_repair_smoke_passed" if ok_smoke else "terminal_synthetic_semantic_repair_failed", pattern=pattern)
    base.update(meta)
    base["synthetic_smoke_detail"] = smoke_detail[-2400:]
    if ok_smoke:
        base.update({
            "blockers": [],
            "coverage_claim": "detector_fixture_smoke_only",
            "evidence_class": "executed_with_manifest",
            "promotion_allowed": False,
            "next_command": "materialize this synthetic semantic pair only after human review confirms it represents the original detector family",
        })
    else:
        if "vuln: expected >=1 hit" in smoke_detail:
            blocker = "synthetic_vulnerable_fixture_still_no_detector_hit"
        elif "clean: expected 0 hits" in smoke_detail:
            blocker = "synthetic_clean_fixture_still_false_positive"
        elif "compile_failed" in smoke_detail:
            blocker = "synthetic_fixture_compile_failed"
        else:
            blocker = "synthetic_smoke_runner_failure"
        base.update({
            "blockers": [blocker],
            "next_command": "hand-author detector-family fixture pair or repair detector predicate; require vulnerable>=1 and clean==0",
            "terminal_evidence_status": "terminal_blocker",
        })
    return base


def _repair_compile_row(p1: Any, row: dict[str, Any], *, runner_python: str) -> dict[str, Any]:
    pattern = _pattern_from_row(row)
    base = _row_base(row, "terminal_repair_workdir_missing", pattern=pattern)
    if not pattern:
        base["blockers"] = ["missing_pattern_argument"]
        return base
    workdir = Path("/private/tmp") / f"auditooor-extract-{pattern}"
    slug = _slug(pattern)
    vuln = workdir / f"{slug}_vulnerable.sol"
    clean = workdir / f"{slug}_clean.sol"
    if not vuln.is_file() or not clean.is_file():
        base.update({
            "blockers": ["generated_fixture_workdir_missing"],
            "expected_vulnerable_fixture": str(vuln),
            "expected_clean_fixture": str(clean),
        })
        return base

    repaired_vuln = workdir / f"{slug}_semantic_repair_vulnerable.sol"
    repaired_clean = workdir / f"{slug}_semantic_repair_clean.sol"
    repaired_vuln.write_text(p1.repair_generated_solidity(vuln.read_text(encoding="utf-8")), encoding="utf-8")
    repaired_clean.write_text(p1.repair_generated_solidity(clean.read_text(encoding="utf-8")), encoding="utf-8")
    compiled, compile_detail = _compile_pair(p1, repaired_vuln, repaired_clean)
    base.update({
        "repaired_clean_fixture": str(repaired_clean),
        "repaired_vulnerable_fixture": str(repaired_vuln),
    })
    if not compiled:
        base.update({
            "status": "terminal_repair_compile_failure",
            "blockers": ["generated_fixture_still_compile_fails_after_local_repair"],
            "compile_detail": compile_detail,
            "next_command": "rerun p1-fixture-extractor with provider feedback or hand-rewrite the generated fixture pair",
        })
        return base

    ok_smoke, smoke_detail = _smoke_pair(p1, pattern, repaired_vuln, repaired_clean, runner_python=runner_python)
    if ok_smoke:
        base.update({
            "status": "local_semantic_repair_smoke_passed",
            "blockers": [],
            "coverage_claim": "detector_fixture_smoke_only",
            "evidence_class": "executed_with_manifest",
        })
        return base
    synthetic = _synthetic_semantic_repair(p1, row, runner_python=runner_python)
    if synthetic and synthetic.get("status") == "local_semantic_repair_smoke_passed":
        synthetic["baseline_local_repair_status"] = "compiled_but_smoke_failed"
        synthetic["baseline_local_repair_detail"] = smoke_detail[-1200:]
        return synthetic
    if "vuln: expected >=1 hit" in smoke_detail:
        status = "terminal_repaired_fixture_vulnerable_no_detector_hit"
        blocker = "detector_predicate_or_vulnerable_fixture_semantics_mismatch"
    elif "clean: expected 0 hits" in smoke_detail:
        status = "terminal_repaired_fixture_clean_false_positive"
        blocker = "detector_predicate_or_clean_fixture_semantics_mismatch"
    else:
        status = "terminal_repaired_fixture_smoke_runner_failure"
        blocker = "smoke_runner_failure"
    base.update({
        "status": status,
        "blockers": [blocker],
        "smoke_detail": smoke_detail[-2400:],
        "next_command": "repair detector predicate or fixture semantics; require vulnerable>=1 and clean==0 before promotion",
    })
    return base


def _terminal_semantic_row(row: dict[str, Any]) -> dict[str, Any]:
    pattern = _pattern_from_row(row)
    status = str(row.get("status") or "")
    if status == "terminal_vulnerable_fixture_no_detector_hit":
        blocker = "detector_predicate_or_vulnerable_fixture_semantics_mismatch"
        next_command = "tighten vulnerable fixture to match detector predicate or update detector predicate with clean fixture guard"
    elif status == "terminal_clean_fixture_false_positive":
        blocker = "detector_predicate_or_clean_fixture_semantics_mismatch"
        next_command = "add detector precision guard or rewrite clean fixture so it expresses the fixed/guarded path"
    elif status == "terminal_fixture_pair_materialized_canonical_smoke_blocked":
        blocker = "canonical_fixture_path_guard_blocks_smoke"
        next_command = "run the pair from a non-skipped temp path or add explicit canonical-fixture smoke override support"
    else:
        blocker = "scanner_autonomy_terminal_semantic_blocker"
        next_command = "inspect row-specific detector and fixture semantics"
    out = _row_base(row, status, pattern=pattern)
    out.update({
        "blockers": [blocker],
        "next_command": next_command,
        "terminal_evidence_status": "terminal_blocker",
    })
    return out


def build_report(execution: Path) -> dict[str, Any]:
    p1 = _load_p1_module()
    runner_python = p1._slither_python() or sys.executable
    payload = _read_json(execution)
    rows = [row for row in payload.get("rows", []) if isinstance(row, dict)]
    repair_rows: list[dict[str, Any]] = []
    for row in rows:
        status = str(row.get("status") or "")
        if status == "terminal_generated_fixture_compile_failure":
            repair_rows.append(_repair_compile_row(p1, row, runner_python=runner_python))
        elif status in {
            "terminal_vulnerable_fixture_no_detector_hit",
            "terminal_clean_fixture_false_positive",
            "terminal_fixture_pair_materialized_canonical_smoke_blocked",
        }:
            synthetic = _synthetic_semantic_repair(p1, row, runner_python=runner_python)
            repair_rows.append(synthetic if synthetic else _terminal_semantic_row(row))
    counts = Counter(str(row.get("status") or "unknown") for row in repair_rows)
    baseline_counts = Counter(str(row.get("baseline_status") or "unknown") for row in repair_rows)
    return {
        "schema": SCHEMA,
        "input_execution": str(execution),
        "baseline_counts": dict(sorted(baseline_counts.items())),
        "status_counts": dict(sorted(counts.items())),
        "rows": repair_rows,
        "canonical_materialization_candidates": counts.get("local_semantic_repair_smoke_passed", 0),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "closed_rows": counts.get("local_semantic_repair_smoke_passed", 0),
        "blockers_left": sum(1 for row in repair_rows if row.get("status") != "local_semantic_repair_smoke_passed"),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Scanner Autonomy Semantic Repair",
        "",
        f"- input execution: `{report['input_execution']}`",
        f"- smoke-passed local repairs: `{report['closed_rows']}`",
        f"- canonical materialization candidates: `{report.get('canonical_materialization_candidates', 0)}`",
        f"- blockers left: `{report['blockers_left']}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in report.get("status_counts", {}).items():
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Rows", "", "| Source | Pattern | Status | Blockers |", "|---|---|---|---|"])
    for row in report.get("rows", []):
        blockers = ",".join(row.get("blockers") or [])
        lines.append(f"| `{row.get('source_id', '')}` | `{row.get('pattern', '')}` | `{row.get('status', '')}` | `{blockers[:160]}` |")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--execution-json", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    ap.add_argument("--manifest-dir", type=Path, help="Optional directory for per-detector semantic repair manifests")
    ap.add_argument("--print-json", action="store_true")
    args = ap.parse_args(argv)
    report = build_report(args.execution_json)
    _write_json(args.out_json, report)
    _write_text(args.out_md, render_markdown(report))
    if args.manifest_dir:
        p1 = _load_p1_module()
        runner_python = p1._slither_python() or sys.executable
        _write_manifest_bundle(report, args.manifest_dir, runner_python=runner_python)
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"[scanner-autonomy-semantic-repair] OK rows={len(report['rows'])} closed={report['closed_rows']} json={args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
