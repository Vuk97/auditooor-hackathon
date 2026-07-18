#!/usr/bin/env python3
"""Parse deep-engine runner artifacts into a structured findings summary.

LANE W4.5 - symbolic-execution / property-fuzzing integration.

The three deep-mode runner scripts ``tools/halmos-runner.sh``,
``tools/medusa-fuzz.sh`` and ``tools/echidna-campaign.sh`` each write a
``auditooor.deep_engine_artifact.v1`` JSON to
``<workspace>/.auditooor/<engine>/artifact.json``. That artifact carries the
engine ``status`` plus the raw ``stdout`` / ``stderr`` text - but nothing
downstream parses the engine output for *failing properties or
counterexamples*. The runner result is effectively dumped to a log.

This tool closes that gap. It:

  1. Scans ``<workspace>/.auditooor/{halmos,medusa,echidna}/artifact.json``.
  2. Runs each engine's combined ``stdout`` + ``stderr`` text through the
     proven conservative parser in ``recon-log-bridge.py`` (the same
     ``_RECON_FP_PATTERNS`` tooling-failure guards + ``_parse_log_stdlib``
     property/counterexample extractor used by ``make recon-log-bridge``).
  3. Emits ``<workspace>/.auditooor/deep-engine-findings/findings.json``
     (schema ``auditooor.deep_engine_findings.v1``) - a normalized record
     the rest of the pipeline (engage_report / detector telemetry /
     ``deep-counterexample-collect.py``) can consume without re-parsing raw
     engine logs.

Always exits 0 unless the workspace argument is malformed: a workspace with
no runner artifacts (engines not installed / skipped) yields an empty but
well-formed findings file. This keeps it offline-safe and CI-friendly.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.deep_engine_findings.v1"
ENGINES = ("halmos", "medusa", "echidna")


def _load_recon_bridge() -> Any:
    """Import recon-log-bridge.py as a module (its filename has a hyphen)."""
    spec = importlib.util.spec_from_file_location(
        "recon_log_bridge", ROOT / "tools" / "recon-log-bridge.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError("cannot load tools/recon-log-bridge.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_engine_text(bridge: Any, engine: str, text: str) -> dict[str, Any]:
    """Parse one engine's combined output text via the recon-bridge logic.

    Returns a normalized finding dict. ``recorded`` means a real failing
    property / counterexample was detected; ``tooling_failure`` means a known
    engine-never-ran pattern fired; ``no_findings`` means a clean run.
    """
    if not text.strip():
        return {
            "engine": engine,
            "verdict": "no_output",
            "reason": "engine artifact carried no stdout/stderr text",
            "target_function": None,
            "input_sequence": [],
            "raw_excerpt": "",
        }
    fp = bridge._check_fp_patterns(text)
    if fp is not None:
        name, reason = fp
        return {
            "engine": engine,
            "verdict": "tooling_failure",
            "tooling_failure_pattern": name,
            "reason": reason,
            "target_function": None,
            "input_sequence": [],
            "raw_excerpt": "\n".join(text.splitlines()[:80]),
        }
    prop = bridge._extract_property(text, engine)
    calls = bridge._extract_calls(text)
    lower = text.lower()
    # A genuine failure marker, not a substring match against benign summary
    # lines like "0 failed" / "Symbolic test result: 8 passed; 0 failed".
    # Anchor: Aztec criterion-i, 2026-05-29 - a fully-passing halmos run
    # (all [PASS], "N passed; 0 failed", no [FAIL]/Counterexample) was misread
    # as a counterexample because the crude `"failed" in lower` test matched
    # the "0 failed" tail of the passing summary.
    explicit_failure = bool(
        re.search(r"\[fail\]", lower)
        or re.search(r"counterexample", lower)
        or re.search(r"\bpanic\b", lower)
        or re.search(r"\bassertion\b.*\b(fail|violat)", lower)
        or re.search(r"\bviolat", lower)
        # non-zero failed/failing count, e.g. "3 failed" / "failing: 2"
        or re.search(r"(?<![0])\b[1-9][0-9]*\s+fail(?:ed|ing|ures?)\b", lower)
        or re.search(r"fail(?:ed|ures?|ing)\s*[:=]\s*[1-9]", lower)
    )
    # Treat an all-pass summary as a hard clean signal that overrides any
    # incidental failure-word match coming from inlined source/lint excerpts.
    clean_summary = bool(
        re.search(r"\b\d+\s+passed;\s*0\s+failed\b", lower)
        or re.search(r"symbolic test result:\s*\d+\s+passed;\s*0\s+failed", lower)
    ) and not re.search(r"\[fail\]|counterexample", lower)
    has_failure = bool(prop) and explicit_failure and not clean_summary
    if has_failure:
        verdict = "counterexample"
        reason = "engine reported a failing property or counterexample"
    else:
        verdict = "no_findings"
        reason = "engine output parsed without a failing property"
    return {
        "engine": engine,
        "verdict": verdict,
        "reason": reason,
        "target_function": prop or (f"{engine}_counterexample" if has_failure else None),
        "input_sequence": calls,
        "raw_excerpt": "\n".join(text.splitlines()[:80]),
    }


def _process_artifact(bridge: Any, engine: str, artifact_path: Path) -> dict[str, Any]:
    """Read one runner artifact.json and turn it into a finding record."""
    record: dict[str, Any] = {
        "engine": engine,
        "artifact_path": str(artifact_path),
        "artifact_present": artifact_path.is_file(),
    }
    if not artifact_path.is_file():
        record.update(
            {
                "engine_status": "missing",
                "verdict": "not_run",
                "reason": "no runner artifact - engine skipped or never invoked",
                "target_function": None,
                "input_sequence": [],
            }
        )
        return record
    try:
        data = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        record.update(
            {
                "engine_status": "unreadable",
                "verdict": "error",
                "reason": f"artifact unreadable: {exc}",
                "target_function": None,
                "input_sequence": [],
            }
        )
        return record
    engine_status = str(data.get("status") or "unknown")
    record["engine_status"] = engine_status
    record["engine_rc"] = data.get("engine_rc")
    record["command"] = data.get("command")
    if engine_status in {"skipped", "tool-unavailable"}:
        record.update(
            {
                "verdict": "not_run",
                "reason": str(data.get("reason") or engine_status),
                "target_function": None,
                "input_sequence": [],
            }
        )
        return record
    combined = "\n".join(
        part
        for part in (str(data.get("stdout") or ""), str(data.get("stderr") or ""))
        if part
    )
    parsed = _parse_engine_text(bridge, engine, combined)
    parsed.pop("engine", None)
    record.update(parsed)
    # C1 fix: a "no-target" status means the engine compiled but found no
    # assertion/property/optimization/custom test to fuzz (e.g. the compile target
    # excluded the property contract). No property loop ran, so the output must NOT be
    # read as a clean negative ("no_findings"). Surface it as a non-execution so
    # deep-freshness / coverage gates do not certify an unexecuted harness as a pass.
    if engine_status == "no-target":
        record.update({
            "verdict": "not_run",
            "reason": str(data.get("reason") or "no-target: no property/assertion test was fuzzed"),
            "target_function": None,
            "input_sequence": [],
        })
        return record
    # An engine-error status means the runner observed a non-zero engine exit
    # (compile/setup/link failure, crytic-compile ABI/import failure, unlinked
    # libraries, etc.). Such a run never reached the fuzz/symbolic loop, so its
    # output must NOT be classified as a clean negative ("no_findings") nor as a
    # real "counterexample" unless a genuine failing property with a
    # counterexample call sequence was actually extracted. Without that signal,
    # downgrade to "tooling_failure" so a crashed engine is never mistaken for
    # either a passed clean-negative or a real finding. Anchor: Aztec
    # criterion-i, 2026-05-29 - echidna unlinked-library failure was misread as
    # a counterexample and medusa ABI-parse failure as a clean no_findings.
    if engine_status == "engine-error" and record.get("verdict") in {
        "counterexample",
        "no_findings",
        "no_output",
    }:
        genuine_counterexample = (
            record.get("verdict") == "counterexample"
            and bool(record.get("input_sequence"))
        )
        if not genuine_counterexample:
            record["verdict"] = "tooling_failure"
            record["tooling_failure_pattern"] = "engine-error-no-property"
            record["reason"] = (
                f"engine exited non-zero (rc={data.get('engine_rc')}) without a "
                "genuine failing property; treated as tooling failure, not a "
                "clean negative or counterexample"
            )
            record["target_function"] = None
            record["input_sequence"] = []
    return record


def collect(workspace: Path) -> dict[str, Any]:
    bridge = _load_recon_bridge()
    findings: list[dict[str, Any]] = []
    for engine in ENGINES:
        artifact_path = workspace / ".auditooor" / engine / "artifact.json"
        findings.append(_process_artifact(bridge, engine, artifact_path))
    verdicts = [f.get("verdict") for f in findings]
    counterexample_count = verdicts.count("counterexample")
    payload = {
        "schema_version": SCHEMA,
        "generated_at": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "workspace": str(workspace),
        "engine_count": len(findings),
        "counterexample_count": counterexample_count,
        "tooling_failure_count": verdicts.count("tooling_failure"),
        "no_findings_count": verdicts.count("no_findings"),
        "not_run_count": verdicts.count("not_run"),
        "has_counterexample": counterexample_count > 0,
        "verdict_counts": {v: verdicts.count(v) for v in sorted(set(verdicts))},
        "findings": findings,
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path (default: <ws>/.auditooor/deep-engine-findings/findings.json)",
    )
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(
            f"[deep-engine-output-parse] ERR workspace not found: {ws}",
            file=sys.stderr,
        )
        return 2
    out_path = (
        args.output.expanduser().resolve()
        if args.output
        else ws / ".auditooor" / "deep-engine-findings" / "findings.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = collect(ws)
    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[deep-engine-output-parse] OK counterexamples={payload['counterexample_count']} "
        f"tooling_failures={payload['tooling_failure_count']} out={out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
