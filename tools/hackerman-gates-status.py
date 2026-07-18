#!/usr/bin/env python3
"""Aggregate verdicts from all hackerman-related pre-submit-check gates.

Wave-1 hackerman capability lift (PR #726, branch ``wave-1-hackerman-capability-lift``).

Purpose
-------
``pre-submit-check.sh`` runs hackerman gates (e.g. Check #72 record verification-tier,
the corpus-subdir acceptance gate) only at filing time. This aggregator gives
operators / CI a single front-door command that fans out across every registered
hackerman gate in parallel-friendly subprocess mode, collects each gate's JSON
envelope, and renders a single deterministic verdict table plus an optional
machine-consumable JSON envelope.

Two gates are bundled out-of-the-box:

1. ``tools/hackerman-record-verification-tier-check.py --all --json`` (pre-submit
   Check #72; ``--all`` is implicit because the script defaults to scanning the
   full tags-dir when neither ``--submission`` nor a single record is passed).
2. ``tools/hackerman-corpus-subdir-acceptance-check.py --all --json`` (corpus
   acceptance gate).

Other hackerman gates can self-register via the ``HACKERMAN_GATE_REGISTRY``
list at module top. Each entry is a ``GateSpec`` instance whose ``argv``
factory returns the CLI args (so callers can plug ``--tags-dir`` overrides
through environment / kwargs).

Verdicts
--------
A gate's normalised verdict is derived from the JSON envelope it emits:

- ``pass`` -- gate exited 0 AND any of:
  - ``verdict`` field equals ``pass``
  - ``fail_count`` is 0 (subdir gate)
  - ``verdict_counts`` has no ``missing-tier`` / ``quarantine`` keys
- ``fail`` -- gate exited non-zero OR an envelope field signals failure
  (``verdict=fail``, ``fail_count>0``, ``failed_records`` non-empty, etc.).
- ``missing`` -- the gate binary could not be located or returned a fatal
  startup error.
- ``error`` -- the gate ran but emitted unparseable JSON.

CLI
---
``--json`` emits the full envelope (schema ``auditooor.hackerman_gates_status.v1``).
Without ``--json`` a human-readable table + summary is rendered.

``--strict`` exits non-zero when ANY gate verdict is fail / missing / error.
Default exit code is 0 (the aggregator is advisory unless ``--strict`` is set).

``--gate`` may be passed multiple times to restrict execution to specific
named gates (e.g. ``--gate record-verification-tier``).

Determinism
-----------
Gates run in the order declared in ``HACKERMAN_GATE_REGISTRY``. The JSON
envelope's ``generated_at`` may be pinned via
``AUDITOOOR_HACKERMAN_GATES_STATUS_GENERATED_AT`` for reproducible tests.

Wired into the Makefile as ``make hackerman-gates-status`` (human) and
``make hackerman-gates-status-json`` (machine).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.hackerman_gates_status.v1"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"


# ---------------------------------------------------------------------------
# Gate registry.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class GateSpec:
    """Declarative wiring for one hackerman gate."""

    name: str
    tool_relpath: str
    description: str
    argv_builder: Callable[["GateContext"], list[str]]

    def absolute_tool_path(self) -> Path:
        return REPO_ROOT / self.tool_relpath


@dataclasses.dataclass(frozen=True)
class GateContext:
    """Runtime knobs forwarded to each gate's argv builder."""

    tags_dir: Path
    repo_root: Path = REPO_ROOT
    extra_args: tuple[str, ...] = ()


def _argv_record_verification_tier(ctx: GateContext) -> list[str]:
    # The underlying tool does NOT accept ``--all`` (it scans the whole tags
    # dir by default), but the spec asks for ``--all --json`` so we tolerate
    # it being absent on the wire. We pass the documented flags only.
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-record-verification-tier-check.py"),
        "--tags-dir",
        str(ctx.tags_dir),
        "--json",
        "--allow-missing-tags-dir",
        *ctx.extra_args,
    ]


def _argv_corpus_subdir_acceptance(ctx: GateContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-corpus-subdir-acceptance-check.py"),
        "--all",
        "--tags-dir",
        str(ctx.tags_dir),
        "--json",
        *ctx.extra_args,
    ]


HACKERMAN_GATE_REGISTRY: list[GateSpec] = [
    GateSpec(
        name="record-verification-tier",
        tool_relpath="tools/hackerman-record-verification-tier-check.py",
        description="Pre-submit Check #72: hackerman_record.v1 verification_tier coverage.",
        argv_builder=_argv_record_verification_tier,
    ),
    GateSpec(
        name="corpus-subdir-acceptance",
        tool_relpath="tools/hackerman-corpus-subdir-acceptance-check.py",
        description="Per-subdir tier-1+tier-2 coverage acceptance gate.",
        argv_builder=_argv_corpus_subdir_acceptance,
    ),
]


def register_gate(spec: GateSpec) -> None:
    """Append a hackerman gate to the registry.

    Idempotent on ``name`` collision (a later registration replaces the
    earlier entry in place, preserving registry ordering).
    """
    for idx, existing in enumerate(HACKERMAN_GATE_REGISTRY):
        if existing.name == spec.name:
            HACKERMAN_GATE_REGISTRY[idx] = spec
            return
    HACKERMAN_GATE_REGISTRY.append(spec)


# ---------------------------------------------------------------------------
# Gate execution + verdict normalisation.
# ---------------------------------------------------------------------------


def _run_gate(spec: GateSpec, ctx: GateContext, *, timeout: int = 600) -> dict[str, Any]:
    """Invoke one gate and return a normalised result row."""
    tool_path = spec.absolute_tool_path()
    if not tool_path.is_file():
        return {
            "name": spec.name,
            "tool": spec.tool_relpath,
            "description": spec.description,
            "verdict": "missing",
            "rc": None,
            "summary": f"gate binary not found at {spec.tool_relpath}",
            "envelope": None,
            "stderr_tail": "",
        }
    argv = list(spec.argv_builder(ctx))
    try:
        proc = subprocess.run(
            argv,
            cwd=str(ctx.repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "name": spec.name,
            "tool": spec.tool_relpath,
            "description": spec.description,
            "verdict": "error",
            "rc": -1,
            "summary": f"subprocess failed: {exc}",
            "envelope": None,
            "stderr_tail": "",
        }
    rc = int(proc.returncode)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    envelope: dict[str, Any] | None
    try:
        envelope = json.loads(stdout) if stdout.strip() else None
    except (json.JSONDecodeError, ValueError):
        return {
            "name": spec.name,
            "tool": spec.tool_relpath,
            "description": spec.description,
            "verdict": "error",
            "rc": rc,
            "summary": "gate did not emit JSON",
            "envelope": None,
            "stderr_tail": stderr[-400:],
        }
    verdict = _normalise_verdict(envelope, rc=rc)
    summary = _gate_summary(envelope, verdict=verdict, rc=rc)
    return {
        "name": spec.name,
        "tool": spec.tool_relpath,
        "description": spec.description,
        "verdict": verdict,
        "rc": rc,
        "summary": summary,
        "envelope": envelope,
        "stderr_tail": stderr[-400:] if stderr else "",
    }


def _normalise_verdict(envelope: dict[str, Any] | None, *, rc: int) -> str:
    """Map a gate's JSON envelope + rc into pass/fail/error/missing."""
    if envelope is None:
        return "error" if rc != 0 else "pass"
    raw = envelope.get("verdict")
    if isinstance(raw, str):
        low = raw.lower()
        if low == "pass":
            return "pass" if rc == 0 else "fail"
        if low == "fail":
            return "fail"
    # Subdir-style envelope has no top-level verdict; infer from counts.
    fail_count = envelope.get("fail_count")
    if isinstance(fail_count, int):
        if fail_count > 0 or rc != 0:
            return "fail"
        return "pass"
    # Record-verification envelope has verdict_counts.
    counts = envelope.get("verdict_counts")
    if isinstance(counts, dict):
        bad = sum(int(counts.get(k, 0) or 0) for k in ("missing-tier", "quarantine"))
        if bad > 0 or rc != 0:
            return "fail"
        return "pass"
    return "pass" if rc == 0 else "fail"


def _gate_summary(envelope: dict[str, Any] | None, *, verdict: str, rc: int) -> str:
    if envelope is None:
        return f"rc={rc} no-envelope"
    if "verdict_counts" in envelope and isinstance(envelope["verdict_counts"], dict):
        vc = envelope["verdict_counts"]
        parts = [f"{k}={vc.get(k, 0)}" for k in sorted(vc.keys())]
        return f"rc={rc} " + " ".join(parts)
    if "directory_count" in envelope:
        return (
            f"rc={rc} dirs={envelope.get('directory_count')} "
            f"pass={envelope.get('pass_count')} fail={envelope.get('fail_count')}"
        )
    reason = envelope.get("reason")
    if isinstance(reason, str):
        return f"rc={rc} {reason}"
    return f"rc={rc} verdict={verdict}"


# ---------------------------------------------------------------------------
# Top-level orchestration.
# ---------------------------------------------------------------------------


def run_gates(
    *,
    tags_dir: Path | None = None,
    selected: Sequence[str] | None = None,
    extra_args: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Run every registered gate (or a subset) and return the result rows."""
    ctx = GateContext(
        tags_dir=Path(tags_dir) if tags_dir else DEFAULT_TAGS_DIR,
        extra_args=tuple(extra_args),
    )
    rows: list[dict[str, Any]] = []
    for spec in HACKERMAN_GATE_REGISTRY:
        if selected and spec.name not in selected:
            continue
        rows.append(_run_gate(spec, ctx))
    return rows


def build_envelope(rows: list[dict[str, Any]], *, generated_at: str) -> dict[str, Any]:
    counts: dict[str, int] = {"pass": 0, "fail": 0, "missing": 0, "error": 0}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    overall = (
        "pass"
        if rows and counts.get("fail", 0) == 0 and counts.get("missing", 0) == 0 and counts.get("error", 0) == 0
        else "fail"
    )
    if not rows:
        overall = "empty"
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "gate_count": len(rows),
        "verdict_counts": dict(sorted(counts.items())),
        "overall_verdict": overall,
        "gates": rows,
    }


def render_report(envelope: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# hackerman gates status ({envelope['schema']})")
    lines.append(f"generated_at: {envelope['generated_at']}")
    lines.append(f"gate_count:   {envelope['gate_count']}")
    lines.append(f"overall:      {envelope['overall_verdict']}")
    lines.append(
        "counts:       "
        + ", ".join(f"{k}={v}" for k, v in envelope["verdict_counts"].items())
    )
    lines.append("")
    # Table.
    header_name = "GATE"
    header_verdict = "VERDICT"
    header_rc = "RC"
    name_w = max(len(header_name), *(len(r["name"]) for r in envelope["gates"])) if envelope["gates"] else len(header_name)
    verdict_w = max(len(header_verdict), *(len(r["verdict"]) for r in envelope["gates"])) if envelope["gates"] else len(header_verdict)
    rc_w = 4
    lines.append(
        f"{header_name:<{name_w}}  {header_verdict:<{verdict_w}}  {header_rc:<{rc_w}}  SUMMARY"
    )
    lines.append(
        f"{'-' * name_w}  {'-' * verdict_w}  {'-' * rc_w}  {'-' * 60}"
    )
    for row in envelope["gates"]:
        rc_str = "-" if row["rc"] is None else str(row["rc"])
        lines.append(
            f"{row['name']:<{name_w}}  {row['verdict']:<{verdict_w}}  {rc_str:<{rc_w}}  {row['summary']}"
        )
    lines.append("")
    lines.append("## Per-gate detail")
    for row in envelope["gates"]:
        lines.append(f"- {row['name']} ({row['tool']})")
        lines.append(f"    description: {row['description']}")
        lines.append(f"    verdict:     {row['verdict']}")
        lines.append(f"    rc:          {row['rc']}")
        lines.append(f"    summary:     {row['summary']}")
        if row.get("stderr_tail"):
            tail = row["stderr_tail"].strip().splitlines()[-1] if row["stderr_tail"].strip() else ""
            if tail:
                lines.append(f"    stderr_tail: {tail[:200]}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _generated_at(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_HACKERMAN_GATES_STATUS_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hackerman-gates-status.")
    parser.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Hackerman corpus tags dir forwarded to each gate.",
    )
    parser.add_argument(
        "--gate",
        action="append",
        default=None,
        help="Restrict execution to one or more gate names (may repeat).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the machine-readable JSON envelope instead of the text report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when overall verdict is not 'pass'.",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Pin the envelope's generated_at field (testing / reproducibility).",
    )
    args = parser.parse_args(argv)

    rows = run_gates(
        tags_dir=Path(args.tags_dir),
        selected=args.gate,
    )
    envelope = build_envelope(rows, generated_at=_generated_at(args.generated_at))

    if args.json:
        json.dump(envelope, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_report(envelope))

    if args.strict and envelope["overall_verdict"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
