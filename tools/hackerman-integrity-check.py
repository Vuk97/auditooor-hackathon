#!/usr/bin/env python3
"""End-to-end Hackerman corpus integrity check (Wave-1, PR #726).

Aggregator that runs ALL hackerman-related checks in sequence and reports a
single overall verdict. This is the operator / CI front door for "is the
hackerman corpus currently coherent?". It chains six independent stage tools
and produces a unified ``auditooor.hackerman_integrity_check.v1`` JSON
envelope plus a human-readable report.

Stages
------
1. ``schema``       -- ``tools/hackerman-record-validate.py`` over the full
                        tags-dir. Parses the trailing
                        ``result: valid=... invalid=... skipped=...`` line.
2. ``tier``         -- ``tools/hackerman-record-verification-tier-check.py``
                        ``--json`` (the script scans the full tags-dir by
                        default; ``--all`` is implied).
3. ``acceptance``   -- ``tools/hackerman-corpus-subdir-acceptance-check.py``
                        ``--all --json`` with the bundled exemption registry.
4. ``dupes``        -- ``tools/hackerman-cross-corpus-dupe-finder.py --json``.
                        The tool also writes its canonical JSONL to a path
                        the caller may override via ``--dupes-jsonl-out``.
                        Any non-exempt duplicate group counts as a fail in
                        ``--strict`` mode.
5. ``stats``        -- ``tools/hackerman-corpus-stats.py --json``.
6. ``distribution`` -- ``tools/hackerman-attack-class-distribution.py --json``.

Each stage is invoked as a subprocess with a deterministic argv builder so
the aggregator can be tested with stub gates / replaced registry entries.

Strict mode
-----------
``--strict`` exits 1 if:

* any stage's verdict is ``fail`` / ``missing`` / ``error``, OR
* the dupes stage produced any non-exempt duplicate group.

Without ``--strict`` the aggregator is advisory and exits 0 unless an
internal error occurs.

Single-stage filter
-------------------
``--stage <name>`` may be repeated to restrict execution to specific stages
(``schema``, ``tier``, ``acceptance``, ``dupes``, ``stats``,
``distribution``). Useful for fast local iteration.

Determinism
-----------
* Stages run in the order declared in ``HACKERMAN_INTEGRITY_STAGES``.
* The envelope's ``generated_at`` may be pinned via the
  ``AUDITOOOR_HACKERMAN_INTEGRITY_GENERATED_AT`` env var or
  ``--generated-at`` so tests stay byte-stable.
* The dupes JSONL output path defaults to
  ``/tmp/integrity_dupes.jsonl`` (matches the Wave-1 PR brief) and can be
  overridden via ``--dupes-jsonl-out``.

Wired into the Makefile as ``make hackerman-integrity-check``.

Attribution
-----------
This module was authored under PR #726 (branch
``wave-1-hackerman-capability-lift``).

* context_pack_id:   ``auditooor.vault_context_pack.v1:resume:960fe73d5414c17f``
* context_pack_hash: ``960fe73d5414c17fa81dfbc30694f47da71bc4aa05b880131d8688d0ce39944f``
* source_refs:
  - ``tools/hackerman-record-validate.py``
  - ``tools/hackerman-record-verification-tier-check.py``
  - ``tools/hackerman-corpus-subdir-acceptance-check.py``
  - ``tools/hackerman-cross-corpus-dupe-finder.py``
  - ``tools/hackerman-corpus-stats.py``
  - ``tools/hackerman-attack-class-distribution.py``
  - ``tools/hackerman-gates-status.py`` (pattern reference)
  - ``audit/corpus_tags/acceptance_exemptions.yaml``
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.hackerman_integrity_check.v1"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_DUPES_JSONL = "/tmp/integrity_dupes.jsonl"

# Verdict tokens (single source of truth for sorting / aggregation).
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_MISSING = "missing"
VERDICT_ERROR = "error"
VERDICT_SKIPPED = "skipped"

_SCHEMA_RESULT_RE = re.compile(
    r"result:\s+valid=(?P<valid>\d+)\s+invalid=(?P<invalid>\d+)\s+skipped=(?P<skipped>\d+)"
)


# ---------------------------------------------------------------------------
# Stage registry.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class StageSpec:
    """Declarative wiring for one integrity-check stage."""

    name: str
    tool_relpath: str
    description: str
    argv_builder: Callable[["StageContext"], list[str]]
    # Parser converts (rc, stdout, stderr) -> dict with keys
    # ``verdict``, ``summary``, ``envelope`` (raw JSON if applicable),
    # ``metrics`` (small flat dict surfaced in the human report).
    result_parser: Callable[[int, str, str], dict[str, Any]]

    def absolute_tool_path(self) -> Path:
        return (REPO_ROOT / self.tool_relpath).resolve() if not Path(self.tool_relpath).is_absolute() else Path(self.tool_relpath)


@dataclasses.dataclass(frozen=True)
class StageContext:
    """Runtime knobs forwarded to each stage's argv builder."""

    tags_dir: Path
    dupes_jsonl_out: Path
    repo_root: Path = REPO_ROOT
    extra_args: tuple[str, ...] = ()


# ---- argv builders --------------------------------------------------------


def _argv_schema(ctx: StageContext) -> list[str]:
    # Intentionally NOT --quiet: we parse the trailing
    # ``result: valid=N invalid=N skipped=N`` line from stdout to surface
    # metrics. The full stdout is ~28k lines / ~2MB for the canonical corpus;
    # acceptable for a once-per-CI invocation.
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-record-validate.py"),
        "--validate-dir",
        str(ctx.tags_dir),
    ]


def _argv_tier(ctx: StageContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-record-verification-tier-check.py"),
        "--tags-dir",
        str(ctx.tags_dir),
        "--json",
        "--allow-missing-tags-dir",
    ]


def _argv_acceptance(ctx: StageContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-corpus-subdir-acceptance-check.py"),
        "--all",
        "--tags-dir",
        str(ctx.tags_dir),
        "--json",
    ]


def _argv_dupes(ctx: StageContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-cross-corpus-dupe-finder.py"),
        "--tags-dir",
        str(ctx.tags_dir),
        "--jsonl-out",
        str(ctx.dupes_jsonl_out),
        "--json",
    ]


def _argv_stats(ctx: StageContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-corpus-stats.py"),
        "--tags-dir",
        str(ctx.tags_dir),
        "--json",
        "--skip-gates",
    ]


def _argv_distribution(ctx: StageContext) -> list[str]:
    return [
        sys.executable,
        str(ctx.repo_root / "tools" / "hackerman-attack-class-distribution.py"),
        "--tags-dir",
        str(ctx.tags_dir),
        "--mode",
        "dense",
        "--json",
    ]


# ---- result parsers -------------------------------------------------------


def _try_parse_json(stdout: str) -> dict[str, Any] | None:
    if not stdout.strip():
        return None
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, dict):
        return obj
    return None


def _parse_schema(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    # hackerman-record-validate emits text. Look for the trailing result: line
    # in stdout OR stderr (with --quiet, the only output is rc).
    combined = (stdout or "") + "\n" + (stderr or "")
    match = _SCHEMA_RESULT_RE.search(combined)
    metrics: dict[str, Any] = {}
    if match:
        metrics = {
            "valid": int(match.group("valid")),
            "invalid": int(match.group("invalid")),
            "skipped": int(match.group("skipped")),
        }
    if rc == 0:
        verdict = VERDICT_PASS
        if metrics:
            summary = (
                f"rc=0 valid={metrics['valid']} invalid={metrics['invalid']} "
                f"skipped={metrics['skipped']}"
            )
        else:
            summary = "rc=0"
    else:
        verdict = VERDICT_FAIL
        if metrics:
            summary = (
                f"rc={rc} valid={metrics['valid']} invalid={metrics['invalid']} "
                f"skipped={metrics['skipped']}"
            )
        else:
            summary = f"rc={rc}"
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": metrics or None,
        "metrics": metrics,
    }


def _parse_tier(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    envelope = _try_parse_json(stdout)
    if envelope is None:
        return {
            "verdict": VERDICT_ERROR if rc != 0 else VERDICT_ERROR,
            "summary": f"rc={rc} no-envelope",
            "envelope": None,
            "metrics": {},
        }
    raw = envelope.get("verdict")
    counts = envelope.get("verdict_counts") or {}
    # Respect the underlying tool's verdict. Quarantine-bucket presence in
    # ``verdict_counts`` is corpus-normal (tier-5 records exist by design)
    # and only counts as fail when the tool itself returned a fail verdict
    # or rc != 0. ``missing-tier`` is the only no-go bucket.
    missing_tier = int(counts.get("missing-tier", 0) or 0)
    if isinstance(raw, str) and raw.lower() == "fail":
        verdict = VERDICT_FAIL
    elif missing_tier > 0 or rc != 0:
        verdict = VERDICT_FAIL
    else:
        verdict = VERDICT_PASS
    audited = envelope.get("audited_hackerman_v1")
    summary = (
        f"rc={rc} audited={audited} "
        + " ".join(f"{k}={counts.get(k, 0)}" for k in sorted(counts.keys()))
    ).strip()
    metrics = {
        "audited": audited,
        "verdict_counts": dict(sorted(counts.items())),
    }
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": envelope,
        "metrics": metrics,
    }


def _parse_acceptance(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    envelope = _try_parse_json(stdout)
    if envelope is None:
        return {
            "verdict": VERDICT_ERROR,
            "summary": f"rc={rc} no-envelope",
            "envelope": None,
            "metrics": {},
        }
    fail_count = envelope.get("fail_count")
    fail_exempt = envelope.get("fail_exempt_count", 0)
    pass_count = envelope.get("pass_count", 0)
    dirs = envelope.get("directory_count", 0)
    # The aggregator considers fail_exempt as PASS (registry-acknowledged).
    # Only un-exempt failures count toward fail verdict.
    if isinstance(fail_count, int) and fail_count > 0:
        verdict = VERDICT_FAIL
    elif rc != 0:
        verdict = VERDICT_FAIL
    else:
        verdict = VERDICT_PASS
    summary = (
        f"rc={rc} dirs={dirs} pass={pass_count} fail={fail_count} "
        f"fail_exempt={fail_exempt}"
    )
    metrics = {
        "directory_count": dirs,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "fail_exempt_count": fail_exempt,
    }
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": envelope,
        "metrics": metrics,
    }


def _parse_dupes(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    envelope = _try_parse_json(stdout)
    if envelope is None:
        return {
            "verdict": VERDICT_ERROR,
            "summary": f"rc={rc} no-envelope",
            "envelope": None,
            "metrics": {},
        }
    summary_obj = envelope.get("summary") or {}
    group_count = summary_obj.get("group_count")
    groups = envelope.get("groups") or []
    if group_count is None:
        group_count = len(groups)
    # Non-exempt groups: any group not marked ``exempt: true``.
    non_exempt = 0
    for grp in groups:
        if isinstance(grp, dict) and not bool(grp.get("exempt")):
            non_exempt += 1
    if rc != 0:
        verdict = VERDICT_FAIL
    else:
        # Pass when no groups at all; otherwise the aggregator surfaces the
        # count and lets --strict mode decide.
        verdict = VERDICT_PASS
    summary = (
        f"rc={rc} groups={group_count} non_exempt={non_exempt} "
        f"records_scanned={summary_obj.get('records_scanned', '?')}"
    )
    metrics = {
        "group_count": group_count,
        "non_exempt_group_count": non_exempt,
        "records_scanned": summary_obj.get("records_scanned"),
        "jsonl_out": summary_obj.get("jsonl_out"),
    }
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": envelope,
        "metrics": metrics,
    }


def _parse_stats(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    envelope = _try_parse_json(stdout)
    if envelope is None:
        return {
            "verdict": VERDICT_ERROR,
            "summary": f"rc={rc} no-envelope",
            "envelope": None,
            "metrics": {},
        }
    stats = envelope.get("stats") or envelope
    total = stats.get("hackerman_v1_total")
    shapes = stats.get("hackerman_v1_by_shape") or {}
    quarantine = stats.get("quarantine") or {}
    quarantine_total = quarantine.get("total", 0) if isinstance(quarantine, dict) else 0
    verdict = VERDICT_PASS if rc == 0 else VERDICT_FAIL
    summary = (
        f"rc={rc} hackerman_v1_total={total} quarantine={quarantine_total} "
        f"shapes=" + ",".join(f"{k}={shapes.get(k, 0)}" for k in sorted(shapes.keys()))
    )
    metrics = {
        "hackerman_v1_total": total,
        "shapes": dict(sorted(shapes.items())),
        "quarantine_total": quarantine_total,
    }
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": envelope,
        "metrics": metrics,
    }


def _parse_distribution(rc: int, stdout: str, stderr: str) -> dict[str, Any]:
    envelope = _try_parse_json(stdout)
    if envelope is None:
        return {
            "verdict": VERDICT_ERROR,
            "summary": f"rc={rc} no-envelope",
            "envelope": None,
            "metrics": {},
        }
    class_totals = envelope.get("class_totals") or {}
    distinct_classes = len(class_totals)
    total_records = sum(int(v or 0) for v in class_totals.values())
    verdict = VERDICT_PASS if rc == 0 else VERDICT_FAIL
    # Sanity heuristic: at least one non-empty class should exist; if a
    # corpus is non-empty (per stats) but distribution shows zero classes,
    # that is a coherence smell.
    if rc == 0 and distinct_classes == 0 and total_records == 0:
        verdict = VERDICT_FAIL
    summary = (
        f"rc={rc} distinct_classes={distinct_classes} total_class_records={total_records}"
    )
    metrics = {
        "distinct_classes": distinct_classes,
        "total_class_records": total_records,
    }
    return {
        "verdict": verdict,
        "summary": summary,
        "envelope": envelope,
        "metrics": metrics,
    }


# ---- canonical stage registry --------------------------------------------


HACKERMAN_INTEGRITY_STAGES: list[StageSpec] = [
    StageSpec(
        name="schema",
        tool_relpath="tools/hackerman-record-validate.py",
        description="Schema validation: hackerman_record.v1 across the full tags-dir.",
        argv_builder=_argv_schema,
        result_parser=_parse_schema,
    ),
    StageSpec(
        name="tier",
        tool_relpath="tools/hackerman-record-verification-tier-check.py",
        description="Verification-tier gate: every hackerman_record.v1 carries a tier.",
        argv_builder=_argv_tier,
        result_parser=_parse_tier,
    ),
    StageSpec(
        name="acceptance",
        tool_relpath="tools/hackerman-corpus-subdir-acceptance-check.py",
        description="Per-subdir tier-1+tier-2 acceptance gate (with exemption registry).",
        argv_builder=_argv_acceptance,
        result_parser=_parse_acceptance,
    ),
    StageSpec(
        name="dupes",
        tool_relpath="tools/hackerman-cross-corpus-dupe-finder.py",
        description="Cross-corpus duplicate detector across all subtrees.",
        argv_builder=_argv_dupes,
        result_parser=_parse_dupes,
    ),
    StageSpec(
        name="stats",
        tool_relpath="tools/hackerman-corpus-stats.py",
        description="Corpus stats: shape counts + quarantine totals.",
        argv_builder=_argv_stats,
        result_parser=_parse_stats,
    ),
    StageSpec(
        name="distribution",
        tool_relpath="tools/hackerman-attack-class-distribution.py",
        description="Attack-class distribution sanity check across subtrees.",
        argv_builder=_argv_distribution,
        result_parser=_parse_distribution,
    ),
]


def register_stage(spec: StageSpec) -> None:
    """Append / replace a stage in the registry (idempotent on name)."""
    for idx, existing in enumerate(HACKERMAN_INTEGRITY_STAGES):
        if existing.name == spec.name:
            HACKERMAN_INTEGRITY_STAGES[idx] = spec
            return
    HACKERMAN_INTEGRITY_STAGES.append(spec)


# ---------------------------------------------------------------------------
# Stage execution.
# ---------------------------------------------------------------------------


def _run_stage(spec: StageSpec, ctx: StageContext, *, timeout: int = 900) -> dict[str, Any]:
    """Invoke one stage and return a normalised result row."""
    tool_path = spec.absolute_tool_path()
    if not tool_path.is_file():
        return {
            "name": spec.name,
            "tool": spec.tool_relpath,
            "description": spec.description,
            "verdict": VERDICT_MISSING,
            "rc": None,
            "summary": f"stage tool not found at {spec.tool_relpath}",
            "envelope": None,
            "metrics": {},
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
            "verdict": VERDICT_ERROR,
            "rc": -1,
            "summary": f"subprocess failed: {exc}",
            "envelope": None,
            "metrics": {},
            "stderr_tail": "",
        }
    rc = int(proc.returncode)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    parsed = spec.result_parser(rc, stdout, stderr)
    return {
        "name": spec.name,
        "tool": spec.tool_relpath,
        "description": spec.description,
        "verdict": parsed.get("verdict", VERDICT_ERROR),
        "rc": rc,
        "summary": parsed.get("summary", f"rc={rc}"),
        "envelope": parsed.get("envelope"),
        "metrics": parsed.get("metrics") or {},
        "stderr_tail": stderr[-400:] if stderr else "",
    }


def run_stages(
    *,
    tags_dir: Path | None = None,
    dupes_jsonl_out: Path | None = None,
    selected: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Run every registered stage (or a subset) and return result rows."""
    ctx = StageContext(
        tags_dir=Path(tags_dir) if tags_dir else DEFAULT_TAGS_DIR,
        dupes_jsonl_out=Path(dupes_jsonl_out) if dupes_jsonl_out else Path(DEFAULT_DUPES_JSONL),
    )
    selected_set = set(selected) if selected else None
    rows: list[dict[str, Any]] = []
    for spec in HACKERMAN_INTEGRITY_STAGES:
        if selected_set is not None and spec.name not in selected_set:
            continue
        rows.append(_run_stage(spec, ctx))
    return rows


# ---------------------------------------------------------------------------
# Envelope + report.
# ---------------------------------------------------------------------------


def _overall_verdict(rows: list[dict[str, Any]], *, strict: bool) -> str:
    """Compute the overall verdict.

    Always considers fail / missing / error as failures.
    In strict mode, also surfaces non-exempt dupe groups as a fail signal.
    """
    if not rows:
        return "empty"
    bad_terminal = {VERDICT_FAIL, VERDICT_MISSING, VERDICT_ERROR}
    if any(r["verdict"] in bad_terminal for r in rows):
        return VERDICT_FAIL
    if strict:
        for row in rows:
            if row["name"] == "dupes":
                non_exempt = int(row.get("metrics", {}).get("non_exempt_group_count", 0) or 0)
                if non_exempt > 0:
                    return VERDICT_FAIL
    return VERDICT_PASS


def build_envelope(
    rows: list[dict[str, Any]],
    *,
    generated_at: str,
    strict: bool = False,
) -> dict[str, Any]:
    counts: dict[str, int] = {
        VERDICT_PASS: 0,
        VERDICT_FAIL: 0,
        VERDICT_MISSING: 0,
        VERDICT_ERROR: 0,
        VERDICT_SKIPPED: 0,
    }
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    overall = _overall_verdict(rows, strict=strict)
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "stage_count": len(rows),
        "verdict_counts": dict(sorted(counts.items())),
        "overall_verdict": overall,
        "strict": bool(strict),
        "stages": rows,
    }


def render_report(envelope: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# hackerman integrity check ({envelope['schema']})")
    lines.append(f"generated_at: {envelope['generated_at']}")
    lines.append(f"stage_count:  {envelope['stage_count']}")
    lines.append(f"overall:      {envelope['overall_verdict']}")
    lines.append(f"strict:       {envelope['strict']}")
    counts_str = ", ".join(f"{k}={v}" for k, v in envelope["verdict_counts"].items() if v)
    lines.append(f"counts:       {counts_str or 'none'}")
    lines.append("")
    # Table.
    header_name = "STAGE"
    header_verdict = "VERDICT"
    header_rc = "RC"
    if envelope["stages"]:
        name_w = max(len(header_name), *(len(r["name"]) for r in envelope["stages"]))
        verdict_w = max(len(header_verdict), *(len(r["verdict"]) for r in envelope["stages"]))
    else:
        name_w = len(header_name)
        verdict_w = len(header_verdict)
    rc_w = 4
    lines.append(
        f"{header_name:<{name_w}}  {header_verdict:<{verdict_w}}  {header_rc:<{rc_w}}  SUMMARY"
    )
    lines.append(f"{'-' * name_w}  {'-' * verdict_w}  {'-' * rc_w}  {'-' * 60}")
    for row in envelope["stages"]:
        rc_str = "-" if row["rc"] is None else str(row["rc"])
        lines.append(
            f"{row['name']:<{name_w}}  {row['verdict']:<{verdict_w}}  {rc_str:<{rc_w}}  {row['summary']}"
        )
    lines.append("")
    lines.append("## Per-stage detail")
    for row in envelope["stages"]:
        lines.append(f"- {row['name']} ({row['tool']})")
        lines.append(f"    description: {row['description']}")
        lines.append(f"    verdict:     {row['verdict']}")
        lines.append(f"    rc:          {row['rc']}")
        lines.append(f"    summary:     {row['summary']}")
        metrics = row.get("metrics") or {}
        if metrics:
            metric_repr = ", ".join(f"{k}={metrics[k]}" for k in sorted(metrics.keys()))
            if len(metric_repr) > 240:
                metric_repr = metric_repr[:237] + "..."
            lines.append(f"    metrics:     {metric_repr}")
        tail = (row.get("stderr_tail") or "").strip()
        if tail:
            last = tail.splitlines()[-1][:200]
            lines.append(f"    stderr_tail: {last}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _generated_at(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_HACKERMAN_INTEGRITY_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "End-to-end hackerman corpus integrity check (PR #726 Wave-1). "
            "Runs schema / tier / acceptance / dupes / stats / distribution "
            "stages and emits a unified verdict."
        )
    )
    parser.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Hackerman corpus tags directory forwarded to each stage.",
    )
    parser.add_argument(
        "--dupes-jsonl-out",
        default=DEFAULT_DUPES_JSONL,
        help=(
            "Where the cross-corpus dupe finder writes its JSONL artifact "
            f"(default: {DEFAULT_DUPES_JSONL})."
        ),
    )
    parser.add_argument(
        "--stage",
        action="append",
        default=None,
        help=(
            "Restrict execution to one or more stages "
            "(schema, tier, acceptance, dupes, stats, distribution). "
            "May be repeated."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the machine-readable JSON envelope instead of the text report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit non-zero when overall verdict is not 'pass' OR any "
            "non-exempt dupe group exists."
        ),
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Pin the envelope's generated_at field (testing / reproducibility).",
    )
    args = parser.parse_args(argv)

    rows = run_stages(
        tags_dir=Path(args.tags_dir),
        dupes_jsonl_out=Path(args.dupes_jsonl_out),
        selected=args.stage,
    )
    envelope = build_envelope(
        rows,
        generated_at=_generated_at(args.generated_at),
        strict=args.strict,
    )

    if args.json:
        json.dump(envelope, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_report(envelope))

    if args.strict and envelope["overall_verdict"] != VERDICT_PASS:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
