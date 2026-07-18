#!/usr/bin/env python3
"""Convert Recon-compatible fuzz logs into auditooor counterexample records.

This bridge is deliberately conservative. It preserves Medusa/Echidna/Halmos
failures as advisory ``deep_counterexample.v1`` records and can emit a skipped
Foundry replay scaffold, but it never marks a failure as proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


RECORD_SCHEMA = "auditooor.deep_counterexample.v1"
MANIFEST_SCHEMA = "auditooor.recon_log_bridge.v1"
ADVISORY = "ADVISORY - converted fuzzer output; not proof until replay is executed."
CALL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\([^)]*\)")
PROP_RE = re.compile(r"\b(?:property|invariant|echidna|test)[A-Za-z0-9_]*\b")

# ---------------------------------------------------------------------------
# Counterexample artifact file names: when one of these files exists in the
# same directory as the fuzz log we know the engine wrote out a trace before
# aborting.  The symbolic-runner.sh and Recon/Chimera runners both use these
# names.  If a tooling-failure pattern also matches the log, the combination
# must be classified as ``tooling_failure_origin`` (advisory) rather than
# silently suppressed — the operator must inspect the artifact.
_CE_ARTIFACT_NAMES: tuple[str, ...] = ("counterexample.txt", "counterexample.json")


def _find_ce_artifact(log_path: Path) -> Path | None:
    """Return the first counterexample artifact found next to ``log_path``, or None."""
    log_dir = log_path.parent
    for name in _CE_ARTIFACT_NAMES:
        candidate = log_dir / name
        if candidate.exists():
            return candidate
    return None


# ---------------------------------------------------------------------------
# False-positive suppression: tooling-failure log patterns
#
# When Foundry/Recon/Chimera/Echidna/Medusa log lines match any of these
# patterns the bridge MUST NOT record a counterexample — the engine never
# ran real fuzzing.  Each entry is (pattern_name, compiled_regex, reason).
#
# Evidence sources:
#   - setup_failure: real Foundry log `[FAIL: failed to set up invariant
#     testing environment: No contracts to fuzz.]`
#     (docs/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md, Issue #2)
#   - no_contracts: `No contracts to fuzz` / `No contracts found`
#     (Foundry invariant runner + real Echidna stderr
#     `echidna: No contracts found in given file`,
#     revert-stableswap-hooks/fuzz_runs/AE_20260502_echidna/stderr.log)
#   - zero_calls: `runs: 0, calls: 0` — engine reported zero fuzz iterations
#     (docs/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md, Issue #2 fix
#     candidate; also seen in CAPABILITY_V3_ITER_001_RESULTS.md 11/11 rows)
#   - panic: `thread '...' panicked` — Rust thread panic in Foundry/engine
#     binary; no fuzzing ran
#     (standard Rust panic format; Foundry forge/chisel emit this on fatal
#     internal errors before any test is executed)
#   - build_failed: `Compiler run failed` / `Error: build failed`
#     (Foundry/solc compilation error; engine never started)
#   - no_tests_found: Medusa `no assertion, property, optimization, or custom
#     tests were found to fuzz`; Echidna `No tests found in ABI`
#     (real Medusa stderr log:
#     revert-stableswap-hooks/fuzz_runs/AE_20260502_medusa/stdout.log)
#   - no_target_contract: Medusa default-project invocation without a target
#     harness (`specify target contract(s)`)
# ---------------------------------------------------------------------------
_RECON_FP_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "setup_failure",
        re.compile(r"failed to set up invariant testing environment", re.IGNORECASE),
        "Foundry invariant runner failed during setUp(); no fuzz calls were made",
    ),
    (
        "no_contracts",
        re.compile(r"no contracts (to fuzz|found)", re.IGNORECASE),
        "Engine found no fuzzable contracts or functions; no fuzz calls were made",
    ),
    (
        "zero_calls",
        re.compile(r"runs:\s*0,\s*calls:\s*0", re.IGNORECASE),
        "Engine reported zero fuzz iterations (runs=0, calls=0); no real fuzzing occurred",
    ),
    (
        "panic",
        re.compile(r"thread\s+'[^']*'\s+panicked", re.IGNORECASE),
        "Rust thread panic in engine/Foundry binary; engine crashed before fuzzing",
    ),
    (
        "build_failed",
        re.compile(r"(Compiler run failed|Error:\s+build failed)", re.IGNORECASE),
        "Solidity compiler or build step failed; engine never ran",
    ),
    (
        "no_tests_found",
        re.compile(
            r"(no assertion, property, optimization, or custom tests were found|no tests found in abi)",
            re.IGNORECASE,
        ),
        "Engine found no testable functions in the harness; no fuzz calls were made",
    ),
    (
        "no_target_contract",
        re.compile(r"specify target contract\(s\)", re.IGNORECASE),
        "Medusa was invoked without an explicit target contract; no fuzz calls were made",
    ),
]


def _check_fp_patterns(text: str) -> tuple[str, str] | None:
    """Scan ``text`` for any known tooling-failure pattern.

    Returns ``(pattern_name, reason)`` for the first match, or ``None``
    when no FP pattern is detected and the log may contain real findings.
    The caller is responsible for recording a ``recon_log_bridge_skipped``
    advisory entry rather than a counterexample.
    """
    for name, pattern, reason in _RECON_FP_PATTERNS:
        if pattern.search(text):
            return name, reason
    return None


def _truth_label_for_pattern(pattern_name: str) -> str:
    if pattern_name == "setup_failure":
        return "setup_failure"
    if pattern_name in {"no_contracts", "no_tests_found"}:
        return "no_targets"
    if pattern_name == "zero_calls":
        return "zero_execution"
    return "tooling_failure"


def _truth_metadata(
    manifest_status: str,
    manifest_reason: str,
    parser_label: str,
    parser_result: dict[str, Any],
    fp_match: tuple[str, str] | None,
) -> dict[str, Any]:
    """Return additive truth-label fields for recon manifests.

    These fields are deliberately derived from existing status/advisory state
    so older consumers can keep using ``status`` while newer finalization code
    can distinguish setup/tooling/parser failures from real no-finding runs.
    """
    parser_status = (
        str(parser_result.get("stdlib_status", ""))
        if parser_label == "stdlib-fallback"
        else "ok"
    )

    if fp_match is not None:
        pattern_name, pattern_reason = fp_match
        truth_label = _truth_label_for_pattern(pattern_name)
        targets_discovered: bool | None
        engine_executed: bool | None
        if truth_label == "no_targets":
            targets_discovered = False
            engine_executed = False
        elif truth_label in {"setup_failure", "zero_execution"}:
            targets_discovered = None
            engine_executed = False
        else:
            targets_discovered = None
            engine_executed = False
        return {
            "truth_label": truth_label,
            "truth_reason": pattern_reason,
            "engine_executed": engine_executed,
            "targets_discovered": targets_discovered,
            "parser_status": parser_status,
            "pattern_name": pattern_name,
        }

    if manifest_status == "recorded":
        return {
            "truth_label": "counterexample",
            "truth_reason": "parser recorded at least one counterexample",
            "engine_executed": True,
            "targets_discovered": True,
            "parser_status": parser_status,
            "pattern_name": "",
        }

    if parser_label == "stdlib-fallback" and parser_status == "error":
        return {
            "truth_label": "parser_failure",
            "truth_reason": manifest_reason or str(parser_result.get("stdlib_reason", "")),
            "engine_executed": None,
            "targets_discovered": None,
            "parser_status": parser_status,
            "pattern_name": "",
        }

    return {
        "truth_label": "no_findings",
        "truth_reason": manifest_reason or "log parsed without a counterexample",
        "engine_executed": True,
        "targets_discovered": True,
        "parser_status": parser_status,
        "pattern_name": "",
    }

# Native parser integration. The optional npm package
# ``@recon-fuzz/log-parser`` ships a Node CLI that consumes Medusa/Echidna
# output and emits a structured JSON document. When the package is
# installed we shell out to it for higher-fidelity parsing; otherwise we
# fall back to the conservative stdlib parser below.
#
# Expected JSON shape (best-effort mapping; see docs/RECON_LOG_BRIDGE.md):
# {
#   "engine": "medusa" | "echidna" | "halmos",
#   "counterexamples": [
#     {
#       "property": "<broken property/invariant name>",
#       "callSequence": [
#         {"target": "Vault", "function": "withdraw", "args": ["200"], "raw": "Vault.withdraw(200)"},
#         ...
#       ],
#       "rawExcerpt": "<engine-specific banner / log slice>"
#     },
#     ...
#   ],
#   "metadata": {"parserVersion": "<semver>"}
# }
#
# We map each entry into a ``deep_counterexample.v1`` record. If the
# package's actual schema differs in field names, the
# ``_native_extract_*`` helpers below are the only place that needs to
# change. See the TODO marker right below.
#
# TODO: verify against actual @recon-fuzz/log-parser output once the
# package is installed in a representative environment.
NATIVE_PARSER_PACKAGE = "@recon-fuzz/log-parser"
NATIVE_PARSER_BIN_ENV = "AUDITOOOR_RECON_LOG_PARSER_BIN"
NATIVE_PARSER_DISABLE_ENV = "AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"
NATIVE_PARSER_VERSION_TIMEOUT = 10
NATIVE_PARSER_RUN_TIMEOUT = 60


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()
    return slug[:80] or "counterexample"


def _extract_property(text: str, engine: str) -> str | None:
    lines = text.splitlines()
    for line in lines:
        lower = line.lower()
        if any(token in lower for token in ("failed", "counterexample", "assertion", "panic")):
            match = PROP_RE.search(line)
            if match:
                return match.group(0)
    if engine == "halmos":
        for line in lines:
            match = PROP_RE.search(line)
            if match:
                return match.group(0)
    return None


def _extract_calls(text: str) -> list[str]:
    calls: list[str] = []
    for line in text.splitlines():
        for match in CALL_RE.findall(line):
            if match not in calls:
                calls.append(match)
    return calls


def _parse_log_stdlib(engine: str, log_path: Path) -> dict[str, Any]:
    """Conservative stdlib parser. Always produces at most one counterexample.

    Returned shape mirrors the legacy single-record contract: ``has_failure``,
    ``status``, ``reason``, ``target_function``, ``input_sequence``,
    ``raw_excerpt``. The newer multi-record orchestrator
    (:func:`parse_log`) wraps this into the same ``counterexamples`` list
    that the native parser emits so downstream code can stay uniform.
    """
    text = log_path.read_text(errors="replace")
    prop = _extract_property(text, engine)
    calls = _extract_calls(text)
    lower = text.lower()
    has_failure = bool(prop) and any(token in lower for token in ("failed", "counterexample", "assertion", "panic", "violat"))
    if not text.strip():
        status = "error"
        reason = "empty log"
    elif has_failure:
        status = "recorded"
        reason = ""
    elif any(token in lower for token in ("started", "testing function", "call sequence")) and not any(token in lower for token in ("pass", "passed", "failed", "counterexample")):
        status = "error"
        reason = "log appears truncated before a pass/fail result"
    else:
        status = "no_findings"
        reason = "log parsed without a failing property or counterexample"
    return {
        "has_failure": has_failure,
        "status": status,
        "reason": reason,
        "target_function": prop or f"{engine}_counterexample",
        "input_sequence": calls,
        "raw_excerpt": "\n".join(text.splitlines()[:80]),
    }


# Backwards-compatible alias retained for any callers that imported the
# legacy private name. New code should prefer :func:`parse_log` (the
# parser-aware orchestrator) or :func:`_parse_log_stdlib` when an
# explicit fallback is desired.
_parse_log = _parse_log_stdlib


# ---- native parser integration -------------------------------------------


def _native_parser_disabled() -> bool:
    raw = os.environ.get(NATIVE_PARSER_DISABLE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _native_parser_command() -> list[str] | None:
    """Return the argv prefix used to invoke the native log-parser, or
    ``None`` when no usable runtime is on PATH.

    Resolution order:
      1. ``AUDITOOOR_RECON_LOG_PARSER_BIN`` env var (operator override; useful
         in tests and for vendored binaries).
      2. ``recon-log-parser`` on PATH (the package installs a bin shim of
         this name when added globally / via ``npm link``).
      3. ``npx --yes @recon-fuzz/log-parser`` (works against a project-local
         install or fetched on demand).

    The function is best-effort: returning ``None`` simply triggers the
    stdlib fallback.
    """
    if _native_parser_disabled():
        return None
    override = os.environ.get(NATIVE_PARSER_BIN_ENV, "").strip()
    if override:
        # Allow either a single binary path or a full quoted argv.
        parts = override.split()
        if parts and (Path(parts[0]).exists() or shutil.which(parts[0])):
            return parts
    direct = shutil.which("recon-log-parser")
    if direct:
        return [direct]
    npx = shutil.which("npx")
    if npx:
        return [npx, "--yes", NATIVE_PARSER_PACKAGE]
    return None


def _native_parser_available(cmd: list[str] | None = None) -> tuple[bool, str]:
    """Probe whether the native parser is installed and runnable.

    Returns ``(available, version_or_reason)``. ``--version`` is the
    canonical probe per the task spec. Any non-zero exit / timeout /
    OSError counts as unavailable; the caller silently falls back.
    """
    cmd = cmd or _native_parser_command()
    if not cmd:
        return False, "no recon-log-parser binary or npx on PATH"
    try:
        proc = subprocess.run(
            cmd + ["--version"],
            capture_output=True,
            text=True,
            timeout=NATIVE_PARSER_VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"native parser probe failed: {exc!s}"
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()[:1]
        return False, f"native parser --version rc={proc.returncode}: {stderr or proc.stdout.strip()!r}"
    version = (proc.stdout or proc.stderr).strip().splitlines()[0] if (proc.stdout or proc.stderr) else ""
    return True, version or "unknown"


def _native_invoke(cmd: list[str], engine: str, log_path: Path) -> dict[str, Any]:
    """Run the native parser against ``log_path`` and return parsed JSON.

    The package is documented to accept ``--engine`` and a positional log
    path and to emit JSON on stdout. We also pass ``--json`` to be
    explicit. Non-zero exit raises :class:`RuntimeError`; the caller
    catches and falls back.
    """
    argv = cmd + ["--engine", engine, "--json", str(log_path)]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=NATIVE_PARSER_RUN_TIMEOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"native parser {NATIVE_PARSER_PACKAGE} exited rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:400]}"
        )
    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise RuntimeError("native parser produced empty stdout")
    try:
        return json.loads(stdout)
    except ValueError as exc:
        raise RuntimeError(f"native parser stdout was not JSON: {exc}") from exc


def _native_call_sequence_to_strings(call_sequence: Any) -> list[str]:
    """Map the native parser's ``callSequence`` into our ``input_sequence``.

    The expected shape per entry is a dict with ``raw`` (preferred), or
    ``target``/``function``/``args``. We tolerate plain strings as well
    so the integration survives minor schema drift.
    """
    out: list[str] = []
    if not isinstance(call_sequence, list):
        return out
    for entry in call_sequence:
        if isinstance(entry, str):
            cleaned = entry.strip()
            if cleaned and cleaned not in out:
                out.append(cleaned)
            continue
        if not isinstance(entry, dict):
            continue
        raw = entry.get("raw")
        if isinstance(raw, str) and raw.strip():
            cleaned = raw.strip()
            if cleaned not in out:
                out.append(cleaned)
            continue
        target = entry.get("target") or entry.get("contract") or ""
        function = entry.get("function") or entry.get("method") or ""
        args = entry.get("args") or []
        if isinstance(args, list):
            args_str = ", ".join(str(a) for a in args)
        else:
            args_str = str(args)
        if function:
            prefix = f"{target}." if target else ""
            cleaned = f"{prefix}{function}({args_str})"
            if cleaned not in out:
                out.append(cleaned)
    return out


def _native_to_counterexamples(
    payload: dict[str, Any],
    engine: str,
    log_path: Path,
) -> list[dict[str, Any]]:
    """Translate a native-parser JSON document into our counterexample
    list (one entry per ``has_failure=True`` record).
    """
    counterexamples: list[dict[str, Any]] = []
    raw_list = payload.get("counterexamples")
    if not isinstance(raw_list, list):
        return counterexamples
    fallback_excerpt = ""
    try:
        fallback_excerpt = "\n".join(log_path.read_text(errors="replace").splitlines()[:80])
    except OSError:
        pass
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        prop = (
            entry.get("property")
            or entry.get("invariant")
            or entry.get("name")
            or ""
        )
        target_function = str(prop).strip() or f"{engine}_counterexample"
        calls = _native_call_sequence_to_strings(entry.get("callSequence") or entry.get("call_sequence"))
        excerpt = entry.get("rawExcerpt") or entry.get("raw_excerpt") or fallback_excerpt
        counterexamples.append({
            "has_failure": True,
            "status": "recorded",
            "reason": "",
            "target_function": target_function,
            "input_sequence": calls,
            "raw_excerpt": str(excerpt)[:8000],
        })
    return counterexamples


def parse_log(engine: str, log_path: Path) -> dict[str, Any]:
    """Multi-record parser orchestrator.

    Returns ``{"parser": <"native"|"stdlib-fallback">, "parser_version":
    <str>, "counterexamples": [...]}``. Each counterexample has the same
    fields as the legacy single-record :func:`_parse_log_stdlib` output.
    The native path can return zero or many counterexamples; the stdlib
    path returns at most one.
    """
    cmd = _native_parser_command()
    if cmd:
        ok, version = _native_parser_available(cmd)
        if ok:
            try:
                payload = _native_invoke(cmd, engine, log_path)
            except RuntimeError as exc:
                # Hard-fail of the native parser is logged on stderr but
                # never a crash for the caller. We fall back so the
                # bridge stays usable in degraded environments.
                print(
                    f"[recon-log-bridge] native parser failed; falling back to stdlib: {exc}",
                    file=sys.stderr,
                )
            else:
                counterexamples = _native_to_counterexamples(payload, engine, log_path)
                return {
                    "parser": "native",
                    "parser_version": version,
                    "counterexamples": counterexamples,
                    "native_payload_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
                }
    parsed = _parse_log_stdlib(engine, log_path)
    counterexamples: list[dict[str, Any]] = []
    if parsed.get("has_failure"):
        counterexamples.append(parsed)
    return {
        "parser": "stdlib-fallback",
        "parser_version": "",
        "counterexamples": counterexamples,
        "stdlib_status": parsed["status"],
        "stdlib_reason": parsed["reason"],
        "stdlib_excerpt": parsed["raw_excerpt"],
    }


def _record_path(out: Path, engine: str, target: str) -> Path:
    return out / f"{engine}-{_slug(target)}.deep_counterexample.v1.json"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _impact_contract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "records", "rows", "impact_contracts"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _selected_impact(row: dict[str, Any]) -> str:
    return _nonempty_text(row.get("selected_impact")) or _nonempty_text(row.get("listed_impact_selected"))


def _severity(row: dict[str, Any]) -> str:
    return (
        _nonempty_text(row.get("severity"))
        or _nonempty_text(row.get("raw_severity"))
        or _nonempty_text(row.get("severity_implied"))
    )


def _locked_impact_contract(workspace: Path, impact_contract_id: str | None) -> tuple[dict[str, Any] | None, str | None]:
    requested = _nonempty_text(impact_contract_id)
    if not requested:
        return None, "blocked_missing_impact_contract: --forge-test-out requires --impact-contract-id"
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        return None, f"blocked_missing_impact_contract: missing {path}"
    try:
        rows = _impact_contract_rows(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        return None, f"blocked_missing_impact_contract: invalid {path}: {exc}"
    row = next((item for item in rows if _nonempty_text(item.get("impact_contract_id")) == requested), None)
    if not row:
        return None, f"blocked_missing_impact_contract: impact_contract_id {requested!r} not found"

    missing: list[str] = []
    if not _selected_impact(row):
        missing.append("selected_impact")
    row_severity = _severity(row)
    if not row_severity or row_severity.lower() == "none":
        missing.append("severity")
    if row.get("exact_impact_row") is False:
        missing.append("exact_impact_row_not_false")
    if not _truthy(row.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")
    if missing:
        return None, f"blocked_missing_impact_contract: impact_contract_id {requested!r} is not locked ({', '.join(missing)})"
    return {
        "impact_contract_id": requested,
        "selected_impact": _selected_impact(row),
        "severity": row_severity,
        "exact_impact_row": row.get("exact_impact_row"),
        "listed_impact_proven": row.get("listed_impact_proven"),
    }, None


def _write_forge_scaffold(path: Path, engine: str, target: str, calls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    escaped_calls = ",\n        ".join(json.dumps(call) for call in calls) or json.dumps("<no parsed calls>")
    path.write_text(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// {ADVISORY}
contract ReconReplayScaffold is Test {{
    string internal constant ENGINE = {json.dumps(engine)};
    string internal constant TARGET = {json.dumps(target)};
    string[] internal calls;

    function setUp() public {{
        string[{len(calls) or 1}] memory parsed = [
        {escaped_calls}
        ];
        for (uint256 i = 0; i < parsed.length; i++) {{
            calls.push(parsed[i]);
        }}
    }}

    function test_replay_scaffold() public {{
        vm.skip(true);
    }}
}}
""")


def build_record(
    workspace: Path,
    engine: str,
    log_path: Path,
    parsed: dict[str, Any],
    row_id: str | None,
    forge_test_out: Path | None,
    impact_contract: dict[str, Any] | None,
    replay_blocker: str | None = None,
) -> dict[str, Any]:
    target = str(parsed["target_function"])
    impact_contract = impact_contract or {}
    promotes_to_poc_work = bool(forge_test_out and impact_contract)
    record: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA,
        "workspace": str(workspace),
        "engine": engine,
        "target_function": target,
        "setup": "Recon log-parser bridge; operator must wire target setup.",
        "input_sequence": parsed["input_sequence"],
        "expected_invariant": target,
        "observed_violation": f"{engine} reported a failing property or counterexample in {log_path}",
        "promotes_to_poc_work": promotes_to_poc_work,
        "evidence_class": "scaffolded_unverified",
        "source_log": str(log_path),
        "row_id": row_id,
        "generated_by": "recon-log-bridge",
        "advisory": ADVISORY,
        "raw_excerpt": parsed["raw_excerpt"],
        "impact_contract_id": impact_contract.get("impact_contract_id") or "",
        "selected_impact": impact_contract.get("selected_impact") or "",
        "severity": impact_contract.get("severity") or "",
        "listed_impact_proven": impact_contract.get("listed_impact_proven"),
        "exact_impact_row": impact_contract.get("exact_impact_row"),
    }
    if forge_test_out:
        record["generated_forge_test_path"] = str(forge_test_out)
        record["replay_command"] = f"forge test --match-path {forge_test_out} -vvv"
    elif replay_blocker:
        record["replay_impossible_reason"] = replay_blocker
        record["promotion_blocker"] = replay_blocker
    else:
        record["replay_impossible_reason"] = "counterexample converted without --forge-test-out; replay scaffold not generated"
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--engine", required=True, choices=["medusa", "echidna", "halmos"])
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--row-id")
    parser.add_argument("--forge-test-out", type=Path)
    parser.add_argument("--impact-contract-id")
    parser.add_argument("--allow-external-log", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    log_path = args.log.expanduser().resolve()
    if not log_path.exists():
        print(f"log file not found: {log_path}", file=sys.stderr)
        return 2
    if not args.allow_external_log and not _is_relative_to(log_path, workspace):
        print(
            f"log file must be inside workspace unless --allow-external-log is set: {log_path}",
            file=sys.stderr,
        )
        return 2
    out = (args.out or workspace / "deep_counterexamples").expanduser().resolve()
    if not _is_relative_to(out, workspace):
        print(f"out directory must stay inside workspace: {out}", file=sys.stderr)
        return 2
    if args.forge_test_out is not None and not _is_relative_to(args.forge_test_out.expanduser().resolve(), workspace):
        print(f"forge test output must stay inside workspace: {args.forge_test_out}", file=sys.stderr)
        return 2
    impact_contract: dict[str, Any] | None = None
    impact_blocker: str | None = None
    effective_forge_test_out = args.forge_test_out
    if args.forge_test_out is not None:
        impact_contract, impact_blocker = _locked_impact_contract(workspace, args.impact_contract_id)
        if impact_blocker:
            effective_forge_test_out = None

    parser_result = parse_log(args.engine, log_path)
    parser_label = parser_result["parser"]
    counterexamples = parser_result["counterexamples"]

    # FP suppression: scan the raw log for tooling-failure patterns BEFORE
    # deciding to record any counterexample.  A match means the engine never
    # completed real fuzzing and any apparent "failure" banner is an artifact.
    # We do NOT silently drop — a recon_log_bridge_skipped advisory is always
    # written into the manifest so operators can see what was suppressed.
    #
    # Tooling-failure-with-counterexample ("tooling_failure_origin") edge case:
    # if the run also left a counterexample artifact file (counterexample.txt /
    # counterexample.json) in the same directory as the log, the combination is
    # classified as ``tooling_failure_origin`` (advisory, rc=0) rather than
    # ``skipped_tooling_failure``.  This prevents the bridge from silently
    # discarding a partial trace that an operator should inspect.
    skipped_advisories: list[dict[str, Any]] = []
    fp_match = _check_fp_patterns(log_path.read_text(errors="replace"))
    if fp_match is not None:
        fp_name, fp_reason = fp_match
        skipped_count = len(counterexamples)
        ce_artifact = _find_ce_artifact(log_path)
        if ce_artifact is not None:
            # Tooling-failure-origin: the run dumped a partial counterexample
            # artifact even though the harness/engine aborted.  Emit a
            # dedicated advisory so the operator can examine the artifact.
            skipped_advisories.append({
                "advisory_type": "recon_log_bridge_skipped",
                "skip_reason": f"tooling_failure_{fp_name}",
                "pattern_name": fp_name,
                "pattern_reason": fp_reason,
                "suppressed_counterexample_count": skipped_count,
            })
            skipped_advisories.append({
                "advisory_type": "recon_log_bridge_tooling_failure_origin",
                "skip_reason": "tooling_failure_origin",
                "pattern_name": fp_name,
                "pattern_reason": fp_reason,
                "counterexample_artifact": str(ce_artifact),
                "note": (
                    "Engine aborted (tooling failure) but left a counterexample artifact. "
                    "The artifact may be a partial trace from a crashed run. "
                    "Inspect the artifact manually before promoting to PoC work."
                ),
            })
        else:
            skipped_advisories.append({
                "advisory_type": "recon_log_bridge_skipped",
                "skip_reason": f"tooling_failure_{fp_name}",
                "pattern_name": fp_name,
                "pattern_reason": fp_reason,
                "suppressed_counterexample_count": skipped_count,
            })
        counterexamples = []

    # Determine manifest status
    has_tooling_failure_origin = any(
        a.get("advisory_type") == "recon_log_bridge_tooling_failure_origin"
        for a in skipped_advisories
    )

    if counterexamples:
        manifest_status = "recorded"
        manifest_reason = ""
    elif has_tooling_failure_origin:
        manifest_status = "tooling_failure_origin"
        manifest_reason = "tooling_failure_origin"
    elif skipped_advisories:
        manifest_status = "skipped_tooling_failure"
        manifest_reason = skipped_advisories[0]["skip_reason"]
    elif parser_label == "stdlib-fallback":
        manifest_status = parser_result.get("stdlib_status", "no_findings")
        manifest_reason = parser_result.get("stdlib_reason", "")
    else:
        manifest_status = "no_findings"
        manifest_reason = "native parser produced no counterexamples"

    parser_limitations = (
        "Recognizes simple Medusa/Echidna/Halmos failure banners and Solidity-like call lines only."
        if parser_label == "stdlib-fallback"
        else f"Native @recon-fuzz/log-parser ({parser_result.get('parser_version') or 'unknown'}); JSON shape mapped per docs/RECON_LOG_BRIDGE.md."
    )

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "workspace": str(workspace),
        "engine": args.engine,
        "source_log": str(log_path),
        "row_id": args.row_id,
        "status": manifest_status,
        "evidence_class": "scaffolded_unverified",
        "generated_at_unix": int(time.time()),
        "records": [],
        "parser": parser_label,
        "parser_version": parser_result.get("parser_version", ""),
        "parser_limitations": parser_limitations,
        "proof_boundary": "Only make poc-execution-record may set final_result=proved or impact_assertion=exploit_impact.",
        "advisory": ADVISORY,
    }
    manifest.update(
        _truth_metadata(
            manifest_status,
            manifest_reason,
            parser_label,
            parser_result,
            fp_match,
        )
    )
    if impact_contract:
        manifest["impact_contract"] = impact_contract
        manifest["impact_contract_id"] = impact_contract["impact_contract_id"]
    if impact_blocker:
        manifest["impact_contract_blocker"] = impact_blocker
        manifest["requested_forge_test_out"] = str(args.forge_test_out)
    if manifest_reason:
        manifest["reason"] = manifest_reason

    if skipped_advisories:
        manifest["skipped_advisories"] = skipped_advisories
        manifest["skipped_count"] = sum(
            a.get("suppressed_counterexample_count", 0) for a in skipped_advisories
        )

    record_paths: list[str] = []
    target_functions: list[str] = []
    for index, parsed in enumerate(counterexamples):
        target = str(parsed["target_function"])
        target_functions.append(target)
        # Disambiguate when the native parser produces several
        # counterexamples that share a target. We only suffix when
        # truly needed so single-record behaviour stays byte-identical
        # to the previous bridge output.
        unique_target = target if index == 0 else f"{target}-{index}"
        record = build_record(
            workspace,
            args.engine,
            log_path,
            parsed,
            args.row_id,
            effective_forge_test_out,
            impact_contract,
            impact_blocker,
        )
        record_path = _record_path(out, args.engine, unique_target)
        _write_json(record_path, record)
        record_paths.append(str(record_path))
        if effective_forge_test_out and index == 0:
            # The forge scaffold path is a single CLI argument; we only
            # write the first counterexample's calls into it. Operators
            # who need per-counterexample scaffolds rerun the bridge
            # with separate ``--forge-test-out`` paths or use the
            # broader ``deep-counterexample-replay-scaffold`` workflow.
            _write_forge_scaffold(
                effective_forge_test_out.expanduser().resolve(),
                args.engine,
                target,
                parsed["input_sequence"],
            )
    if record_paths:
        manifest["records"] = record_paths
        manifest["target_function"] = target_functions[0]
        if len(target_functions) > 1:
            manifest["target_functions"] = target_functions

    manifest_path = out / "recon_log_bridge_manifest.json"
    _write_json(manifest_path, manifest)
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
