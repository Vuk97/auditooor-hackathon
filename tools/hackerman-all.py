#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - one-shot aggregator.

Single command that runs the full hackerman test + lint + gate suite in
sequence and emits a combined per-stage verdict plus an overall PASS/FAIL.

Stages (stable order):

    1. ``schema``      - tools/hackerman-record-validate.py (full tags dir)
    2. ``tier``        - tools/hackerman-record-verification-tier-check.py --json
    3. ``acceptance``  - tools/hackerman-corpus-subdir-acceptance-check.py --all --strict
    4. ``unit-tests``  - python3 -m unittest discover tools/tests -p test_hackerman_*.py
    5. ``vault-tests`` - python3 -m unittest discover tools/tests -p test_vault_*.py
    6. ``stats``       - tools/hackerman-corpus-stats.py
    7. ``integrity``   - tools/hackerman-integrity-check.py  (only if the file exists)

The aggregator emits one of two output forms:

    * ``--json``: a canonical ``auditooor.hackerman_all.v1`` envelope (deterministic,
      generated_at-overridable via env or flag, byte-identical between runs when
      timestamp + stages are pinned).
    * default: a human-readable multi-section text report.

The overall verdict is ``pass`` iff every executed stage's verdict is ``pass``
or ``skipped`` (an absent integrity tool is skipped). Any ``fail`` / ``error``
flips overall to ``fail`` and (with ``--strict``, the default) exits non-zero.

Wiring:

    * ``make hackerman-all``       -> human report (strict)
    * ``make hackerman-all-json``  -> JSON envelope (strict)

Determinism guarantees:

    * Stage order is fixed by ``STAGES``.
    * Verdict aggregation is pure: a stage's verdict is a function of its
      subprocess returncode + parsed stdout markers, never wall-clock time.
    * ``--generated-at`` (or env ``AUDITOOOR_HACKERMAN_ALL_GENERATED_AT``)
      pins the envelope timestamp; this is what the unit tests rely on.
    * Subprocess stdout is captured but only summary lines are surfaced
      in the text report (keeps output under the 1MB cap).

The aggregator never edits files. It is read-only against the corpus tree
and the tests it invokes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCHEMA = "auditooor.hackerman_all.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"

# Stage registry. Each entry: (id, human_label).
STAGES: Tuple[Tuple[str, str], ...] = (
    ("schema", "Schema validation (hackerman-record-validate)"),
    ("tier", "Verification-tier gate (hackerman-record-verification-tier-check)"),
    ("acceptance", "Acceptance gate with exemptions (hackerman-corpus-subdir-acceptance-check)"),
    ("unit-tests", "Hackerman unit tests (tools/tests/test_hackerman_*.py)"),
    ("vault-tests", "Vault MCP callable tests (tools/tests/test_vault_*.py)"),
    ("stats", "Corpus stats (hackerman-corpus-stats)"),
    ("integrity", "End-to-end integrity check (hackerman-integrity-check, optional)"),
)
STAGE_IDS = tuple(s[0] for s in STAGES)

# `--validate-all-tags` is the spec-level name; the underlying flag on
# hackerman-record-validate.py is ``--strict-all``. We default to the
# corpus-compatible (non-strict-all) mode so legacy verdict-tag YAMLs are
# skipped. The ``--validate-all-tags`` orchestrator flag flips that to
# ``--strict-all``.
DEFAULT_TIMEOUT_SECONDS = 900


@dataclass
class StageResult:
    stage: str
    label: str
    verdict: str  # pass | fail | error | skipped | missing
    returncode: int
    summary: str
    duration_seconds: float
    stdout_tail: str = ""
    stderr_tail: str = ""
    cmd: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "label": self.label,
            "verdict": self.verdict,
            "returncode": self.returncode,
            "summary": self.summary,
            "duration_seconds": round(self.duration_seconds, 3),
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "cmd": list(self.cmd),
        }


# --- subprocess helpers --------------------------------------------------


def _tail(s: str, max_chars: int = 2000) -> str:
    if not s:
        return ""
    if len(s) <= max_chars:
        return s
    return "..." + s[-max_chars:]


def _run(cmd: Sequence[str], *, timeout: int, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        return 124, exc.stdout or "", (exc.stderr or "") + f"\n[hackerman-all] timeout after {timeout}s\n", elapsed
    elapsed = time.monotonic() - started
    return proc.returncode, proc.stdout or "", proc.stderr or "", elapsed


# --- stage runners -------------------------------------------------------


def run_stage_schema(args: argparse.Namespace) -> StageResult:
    tool = REPO_ROOT / "tools" / "hackerman-record-validate.py"
    cmd = [sys.executable, str(tool), "--validate-dir", str(args.tags_dir)]
    if args.validate_all_tags:
        cmd.append("--strict-all")
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    summary = _parse_schema_summary(out)
    if rc != 0:
        verdict = "fail"
    elif "invalid=0" not in summary and summary:
        verdict = "fail"
    else:
        verdict = "pass"
    return StageResult(
        stage="schema",
        label=STAGES[0][1],
        verdict=verdict,
        returncode=rc,
        summary=summary or "no result line emitted",
        duration_seconds=dur,
        stdout_tail=_tail(out, 600),
        stderr_tail=_tail(err, 600),
        cmd=cmd,
    )


def _parse_schema_summary(stdout: str) -> str:
    # hackerman-record-validate.py emits a trailing line:
    #   result: valid=N invalid=M skipped=K
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("result:") and "valid=" in line:
            return line
    return ""


def run_stage_tier(args: argparse.Namespace) -> StageResult:
    tool = REPO_ROOT / "tools" / "hackerman-record-verification-tier-check.py"
    cmd = [sys.executable, str(tool), "--tags-dir", str(args.tags_dir), "--json"]
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    summary, verdict = _parse_tier_summary(out, rc)
    return StageResult(
        stage="tier",
        label=STAGES[1][1],
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=dur,
        stdout_tail=_tail(out, 600),
        stderr_tail=_tail(err, 600),
        cmd=cmd,
    )


def _parse_tier_summary(stdout: str, rc: int) -> Tuple[str, str]:
    try:
        payload = json.loads(stdout)
    except Exception:
        if rc != 0:
            return ("JSON parse failed; rc != 0", "fail")
        return ("JSON parse failed", "error")
    audited = payload.get("audited_hackerman_v1", 0)
    failed = len(payload.get("failed_records") or [])
    quarantined = len(payload.get("quarantine_records") or [])
    summary = (
        f"audited={audited} failed={failed} quarantined={quarantined}"
    )
    if rc != 0 or failed > 0:
        return summary, "fail"
    return summary, "pass"


def run_stage_acceptance(args: argparse.Namespace) -> StageResult:
    tool = REPO_ROOT / "tools" / "hackerman-corpus-subdir-acceptance-check.py"
    cmd = [
        sys.executable,
        str(tool),
        "--all",
        "--tags-dir",
        str(args.tags_dir),
        "--strict",
        "--json",
    ]
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    summary, verdict = _parse_acceptance_summary(out, rc)
    return StageResult(
        stage="acceptance",
        label=STAGES[2][1],
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=dur,
        stdout_tail=_tail(out, 800),
        stderr_tail=_tail(err, 600),
        cmd=cmd,
    )


def _parse_acceptance_summary(stdout: str, rc: int) -> Tuple[str, str]:
    try:
        payload = json.loads(stdout)
    except Exception:
        if rc != 0:
            return ("JSON parse failed; rc != 0", "fail")
        return ("JSON parse failed", "error")
    dirs = payload.get("directory_count", 0)
    fails = payload.get("fail_count", 0)
    fails_exempt = payload.get("fail_exempt_count", 0)
    exempt = payload.get("exemptions_loaded", 0)
    summary = (
        f"subtrees={dirs} fails={fails} fails_exempt={fails_exempt} "
        f"exemptions_loaded={exempt}"
    )
    # rc==0 means: strict gate accepted the result (any failures are exempt).
    # rc!=0 means: strict gate refused (a non-exempt subtree failed).
    if rc != 0:
        return summary, "fail"
    return summary, "pass"


def run_stage_unit_tests(args: argparse.Namespace) -> StageResult:
    return _run_unittest_discover(
        stage="unit-tests",
        label=STAGES[3][1],
        pattern="test_hackerman_*.py",
        args=args,
    )


def run_stage_vault_tests(args: argparse.Namespace) -> StageResult:
    return _run_unittest_discover(
        stage="vault-tests",
        label=STAGES[4][1],
        pattern="test_vault_*.py",
        args=args,
    )


def _run_unittest_discover(*, stage: str, label: str, pattern: str, args: argparse.Namespace) -> StageResult:
    cmd = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "tools/tests/",
        "-p",
        pattern,
    ]
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    # unittest prints its summary to stderr.
    combined = err or out
    summary = _parse_unittest_summary(combined)
    if rc == 0 and summary.startswith("ok "):
        verdict = "pass"
    elif rc != 0:
        verdict = "fail"
    else:
        verdict = "error"
    return StageResult(
        stage=stage,
        label=label,
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=dur,
        stdout_tail=_tail(out, 600),
        stderr_tail=_tail(err, 1200),
        cmd=cmd,
    )


_UNITTEST_RAN_RE = re.compile(r"^Ran (\d+) tests? in ([0-9.]+)s\s*$")


def _parse_unittest_summary(stream: str) -> str:
    lines = stream.splitlines()
    ran_line = ""
    verdict_line = ""
    for line in reversed(lines):
        s = line.strip()
        if not verdict_line and (s == "OK" or s.startswith("OK ") or s == "FAILED" or s.startswith("FAILED ")):
            verdict_line = s
        if not ran_line:
            m = _UNITTEST_RAN_RE.match(s)
            if m:
                ran_line = s
        if ran_line and verdict_line:
            break
    if not ran_line and not verdict_line:
        return "no unittest summary line"
    state = "ok" if verdict_line.startswith("OK") else "fail"
    return f"{state} {ran_line} {verdict_line}".strip()


def run_stage_stats(args: argparse.Namespace) -> StageResult:
    tool = REPO_ROOT / "tools" / "hackerman-corpus-stats.py"
    cmd = [
        sys.executable,
        str(tool),
        "--tags-dir",
        str(args.tags_dir),
        "--skip-gates",
    ]
    if args.generated_at:
        cmd.extend(["--generated-at", args.generated_at])
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    summary = _parse_stats_summary(out)
    verdict = "pass" if rc == 0 else "fail"
    return StageResult(
        stage="stats",
        label=STAGES[5][1],
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=dur,
        stdout_tail=_tail(out, 600),
        stderr_tail=_tail(err, 600),
        cmd=cmd,
    )


def _parse_stats_summary(stdout: str) -> str:
    m = re.search(r"total_records\s*[:=]\s*(\d+)", stdout)
    if m:
        return f"total_records={m.group(1)}"
    m = re.search(r"Total records[^\d]*(\d+)", stdout)
    if m:
        return f"total_records={m.group(1)}"
    # Fallback: count subtree headers.
    sub = re.findall(r"^### ", stdout, flags=re.MULTILINE)
    if sub:
        return f"subtree_sections={len(sub)}"
    return "stats emitted"


def run_stage_integrity(args: argparse.Namespace) -> StageResult:
    tool = REPO_ROOT / "tools" / "hackerman-integrity-check.py"
    if not tool.is_file():
        return StageResult(
            stage="integrity",
            label=STAGES[6][1],
            verdict="skipped",
            returncode=0,
            summary="hackerman-integrity-check.py not present (skipped per spec)",
            duration_seconds=0.0,
            stdout_tail="",
            stderr_tail="",
            cmd=[],
        )
    cmd = [
        sys.executable,
        str(tool),
        "--tags-dir",
        str(args.tags_dir),
        "--json",
    ]
    if args.generated_at:
        cmd.extend(["--generated-at", args.generated_at])
    rc, out, err, dur = _run(cmd, timeout=args.timeout)
    summary, verdict = _parse_integrity_summary(out, rc)
    return StageResult(
        stage="integrity",
        label=STAGES[6][1],
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=dur,
        stdout_tail=_tail(out, 800),
        stderr_tail=_tail(err, 600),
        cmd=cmd,
    )


def _parse_integrity_summary(stdout: str, rc: int) -> Tuple[str, str]:
    try:
        payload = json.loads(stdout)
    except Exception:
        if rc != 0:
            return ("JSON parse failed; rc != 0", "fail")
        return ("JSON parse failed", "error")
    verdict = payload.get("overall_verdict") or payload.get("verdict") or "unknown"
    stages = payload.get("stages") or []
    summary = f"overall={verdict} stages={len(stages)}"
    if rc != 0 or verdict not in ("pass", "skipped"):
        return summary, "fail"
    return summary, "pass"


# --- aggregator ----------------------------------------------------------


STAGE_RUNNERS = {
    "schema": run_stage_schema,
    "tier": run_stage_tier,
    "acceptance": run_stage_acceptance,
    "unit-tests": run_stage_unit_tests,
    "vault-tests": run_stage_vault_tests,
    "stats": run_stage_stats,
    "integrity": run_stage_integrity,
}


def run_all(args: argparse.Namespace) -> List[StageResult]:
    selected = args.stage or list(STAGE_IDS)
    results: List[StageResult] = []
    for stage_id in selected:
        runner = STAGE_RUNNERS.get(stage_id)
        if runner is None:
            results.append(
                StageResult(
                    stage=stage_id,
                    label="unknown",
                    verdict="error",
                    returncode=2,
                    summary=f"unknown stage id: {stage_id}",
                    duration_seconds=0.0,
                )
            )
            continue
        results.append(runner(args))
        if args.fail_fast and results[-1].verdict in ("fail", "error"):
            break
    return results


def overall_verdict(results: Sequence[StageResult]) -> str:
    if not results:
        return "fail"
    for r in results:
        if r.verdict in ("fail", "error"):
            return "fail"
    return "pass"


def render_report(results: Sequence[StageResult], *, generated_at: str, overall: str, tags_dir: Path) -> str:
    lines: List[str] = []
    lines.append("# hackerman-all aggregator")
    lines.append("")
    lines.append(f"schema: {SCHEMA}")
    lines.append(f"generated_at: {generated_at}")
    lines.append(f"tags_dir: {tags_dir}")
    lines.append(f"overall_verdict: {overall}")
    lines.append("")
    lines.append("## Per-stage verdicts")
    lines.append("")
    width_stage = max(len(r.stage) for r in results) if results else 6
    width_verd = max(len(r.verdict) for r in results) if results else 7
    for r in results:
        lines.append(
            f"- {r.stage.ljust(width_stage)}  {r.verdict.ljust(width_verd)}  "
            f"rc={r.returncode}  {r.duration_seconds:6.2f}s  {r.summary}"
        )
    lines.append("")
    lines.append("## Per-stage labels")
    lines.append("")
    for r in results:
        lines.append(f"- {r.stage}: {r.label}")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_json_envelope(results: Sequence[StageResult], *, generated_at: str, tags_dir: Path) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "tags_dir": str(tags_dir),
        "overall_verdict": overall_verdict(results),
        "stage_count": len(results),
        "stages": [r.to_json() for r in results],
    }


# --- CLI -----------------------------------------------------------------


def _resolve_generated_at(arg: Optional[str]) -> str:
    if arg:
        return arg
    env = os.environ.get("AUDITOOOR_HACKERMAN_ALL_GENERATED_AT")
    if env:
        return env
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hackerman one-shot aggregator (schema + tier + acceptance + tests + stats + integrity).",
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Hackerman corpus tags directory (default: audit/corpus_tags/tags).",
    )
    parser.add_argument(
        "--validate-all-tags",
        action="store_true",
        help="Pass --strict-all to the schema validator (validate every YAML, "
        "including non-hackerman legacy verdict tags).",
    )
    parser.add_argument(
        "--stage",
        action="append",
        choices=STAGE_IDS,
        help="Restrict execution to one or more stages (may be repeated).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON envelope instead of the human-readable report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when overall verdict != pass (default: advisory).",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first fail/error stage.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-stage subprocess timeout in seconds (default: 900).",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="Pin the envelope timestamp (also via env "
        "AUDITOOOR_HACKERMAN_ALL_GENERATED_AT).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    args.generated_at = _resolve_generated_at(args.generated_at)
    args.tags_dir = Path(args.tags_dir).expanduser().resolve()

    results = run_all(args)
    overall = overall_verdict(results)

    if args.json:
        payload = build_json_envelope(results, generated_at=args.generated_at, tags_dir=args.tags_dir)
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(
            render_report(results, generated_at=args.generated_at, overall=overall, tags_dir=args.tags_dir)
        )

    if args.strict and overall != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
