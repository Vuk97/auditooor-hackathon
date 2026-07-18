#!/usr/bin/env python3
"""Smoke-check Phase II standalone capability tools.

The harness is intentionally lightweight: it only runs bounded CLI probes for
known Phase II tools that exist in the checkout and marks absent tools pending.
"""

from __future__ import annotations

import argparse
import glob
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.phase_ii_capability_smoke.v1"
TOOL_NAME = "phase-ii-capability-smoke"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_EXCERPT_CHARS = 1200
MAX_SAMPLE_PROBES_PER_CAPABILITY = 2
STATUS_PRESENT_PASS = "present-pass"
STATUS_PRESENT_FAIL = "present-fail"
STATUS_PENDING = "pending"
PROBE_STATUS_PASS = "pass"
PROBE_STATUS_FAIL = "fail"


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    tool_candidates: tuple[str, ...]
    source_refs: tuple[str, ...]
    help_args: tuple[str, ...] = ("--help",)
    sample_path_candidates: tuple[str, ...] = ()
    sample_arg_template: tuple[str, ...] = ()


DEFAULT_CAPABILITIES: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        capability_id="SMIV",
        tool_candidates=(
            "tools/semantic-match-invariant-verifier.py",
            "tools/smiv-semantic-match-invariant-verifier.py",
            "tools/live-target-intelligence-report.py",
        ),
        source_refs=(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:121",
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:124",
            "reports/v3_iter_2026-05-24/lane_PROPOSAL_VS_EXISTING_AUDIT/results.md:199",
        ),
        sample_path_candidates=(
            "reports/v3_iter_2026-05-23/lane_HB_P1_HYPERBRIDGE_DOGFOOD",
        ),
        sample_arg_template=(
            "--workspace",
            "{sample_path}",
            "--json",
            "--top-n",
            "3",
            "--triager-precheck-budget",
            "0",
        ),
    ),
    CapabilitySpec(
        capability_id="DNS",
        tool_candidates=("tools/defender-narrative-simulator.py",),
        source_refs=(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:128",
            "reports/v3_iter_2026-05-24/lane_PHASE_II_2_DNS/results.md:5",
        ),
        sample_path_candidates=(
            "reports/v3_iter_2026-05-24/lane_PHASE_II_2_DNS/sample.json",
            "tools/tests/fixtures/phase_ii_capability_smoke/dns.json",
        ),
        sample_arg_template=("{sample_path}",),
    ),
    CapabilitySpec(
        capability_id="FDASR",
        tool_candidates=("tools/fork-divergence-attack-surface-ranker.py",),
        source_refs=(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:121",
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:126",
            "reports/v3_iter_2026-05-24/lane_PROPOSAL_VS_EXISTING_AUDIT/results.md:201",
        ),
        sample_path_candidates=(
            "reports/v3_iter_2026-05-24/lane_PHASE_II_1_FDASR/sample.json",
            "tools/tests/fixtures/phase_ii_capability_smoke/fdasr.json",
        ),
        sample_arg_template=("--input", "{sample_path}"),
    ),
    CapabilitySpec(
        capability_id="AHDH",
        tool_candidates=("tools/adversarial-hypothesis-differential-hunter.py",),
        source_refs=(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:132",
            "reports/v3_iter_2026-05-24/lane_PROPOSAL_VS_EXISTING_AUDIT/results.md:202",
        ),
        sample_path_candidates=(
            "reports/v3_iter_2026-05-24/lane_PHASE_II_3_AHDH/sample.json",
            "tools/tests/fixtures/phase_ii_capability_smoke/ahdh.json",
        ),
        sample_arg_template=("--input", "{sample_path}"),
    ),
    CapabilitySpec(
        capability_id="PFORPD",
        tool_candidates=(
            "tools/post-filing-outcome-replay-pattern-distiller.py",
            "tools/post-filing-outcome-replay.py",
        ),
        source_refs=(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md:136",
            "reports/v3_iter_2026-05-24/lane_PROPOSAL_VS_EXISTING_AUDIT/results.md:203",
        ),
        sample_path_candidates=(
            "reports/v3_iter_2026-05-24/lane_PHASE_II_4_PFORPD/sample.jsonl",
            "reports/v3_iter_2026-05-24/lane_PHASE_II_4_PFORPD/sample.json",
            "tools/tests/fixtures/phase_ii_capability_smoke/pforpd.jsonl",
            "tools/tests/fixtures/phase_ii_capability_smoke/pforpd.json",
            "reference/outcomes.jsonl",
        ),
        sample_arg_template=("--outcomes", "{sample_path}"),
    ),
)


def _as_path(repo_root: Path, token: str) -> Path:
    path = Path(token).expanduser()
    if path.is_absolute():
        return path
    return repo_root / path


def _display_path(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _excerpt(value: str | bytes | None, max_chars: int) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 16)].rstrip() + "\n...[truncated]"


def _has_glob_magic(token: str) -> bool:
    return any(char in token for char in "*?[")


def _discover_tool(repo_root: Path, spec: CapabilitySpec) -> tuple[Path | None, str]:
    for candidate in spec.tool_candidates:
        path = _as_path(repo_root, candidate)
        if path.is_file():
            return path, _display_path(repo_root, path)
    first = _as_path(repo_root, spec.tool_candidates[0])
    return None, _display_path(repo_root, first)


def _discover_sample_paths(repo_root: Path, spec: CapabilitySpec) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for candidate in spec.sample_path_candidates:
        matches: Iterable[str]
        if _has_glob_magic(candidate):
            pattern = str(_as_path(repo_root, candidate))
            matches = sorted(glob.glob(pattern))
        else:
            path = _as_path(repo_root, candidate)
            matches = [str(path)] if (path.is_file() or path.is_dir()) else []
        for match in matches:
            path = Path(match)
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
            if len(out) >= MAX_SAMPLE_PROBES_PER_CAPABILITY:
                return out
    return out


def _format_args(template: tuple[str, ...], repo_root: Path, sample_path: Path) -> tuple[list[str], list[str]]:
    actual: list[str] = []
    rendered: list[str] = []
    display = _display_path(repo_root, sample_path)
    for part in template:
        actual.append(part.replace("{sample_path}", str(sample_path)))
        rendered.append(part.replace("{sample_path}", display))
    return actual, rendered


def _probe_command(tool_path: Path, args: list[str]) -> list[str]:
    if tool_path.suffix == ".py":
        return [sys.executable, str(tool_path), *args]
    return [str(tool_path), *args]


def _render_command(repo_root: Path, tool_path: Path, rendered_args: list[str]) -> str:
    executable = "python3" if tool_path.suffix == ".py" else _display_path(repo_root, tool_path)
    parts = [executable]
    if tool_path.suffix == ".py":
        parts.append(_display_path(repo_root, tool_path))
    parts.extend(rendered_args)
    return shlex.join(parts)


def _run_probe(
    *,
    repo_root: Path,
    capability_id: str,
    probe_id: str,
    tool_path: Path,
    actual_args: list[str],
    rendered_args: list[str],
    timeout_seconds: float,
    max_excerpt_chars: int,
) -> dict[str, Any]:
    rendered_command = _render_command(repo_root, tool_path, rendered_args)
    try:
        proc = subprocess.run(
            _probe_command(tool_path, actual_args),
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        exit_code: int | None = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        stdout = exc.stdout
        stderr = exc.stderr
        timed_out = True

    return {
        "probe_id": probe_id,
        "capability_id": capability_id,
        "status": PROBE_STATUS_PASS if exit_code == 0 and not timed_out else PROBE_STATUS_FAIL,
        "command": rendered_command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_excerpt": _excerpt(stdout, max_excerpt_chars),
        "stderr_excerpt": _excerpt(stderr, max_excerpt_chars),
    }


def smoke_capability(
    repo_root: Path,
    spec: CapabilitySpec,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_excerpt_chars: int = DEFAULT_MAX_EXCERPT_CHARS,
) -> dict[str, Any]:
    tool_path, tool_display = _discover_tool(repo_root, spec)
    source_refs = list(spec.source_refs)

    if tool_path is None:
        return {
            "capability_id": spec.capability_id,
            "tool_path": tool_display,
            "status": STATUS_PENDING,
            "command": "",
            "exit_code": None,
            "stdout_excerpt": "",
            "stderr_excerpt": "tool path not present; capability integration pending",
            "source_refs": source_refs,
            "probes": [],
        }

    probes: list[dict[str, Any]] = [
        _run_probe(
            repo_root=repo_root,
            capability_id=spec.capability_id,
            probe_id="help",
            tool_path=tool_path,
            actual_args=list(spec.help_args),
            rendered_args=list(spec.help_args),
            timeout_seconds=timeout_seconds,
            max_excerpt_chars=max_excerpt_chars,
        )
    ]

    if spec.sample_arg_template:
        for index, sample_path in enumerate(_discover_sample_paths(repo_root, spec), start=1):
            actual_args, rendered_args = _format_args(spec.sample_arg_template, repo_root, sample_path)
            sample_ref = f"sample:{_display_path(repo_root, sample_path)}"
            if sample_ref not in source_refs:
                source_refs.append(sample_ref)
            probes.append(
                _run_probe(
                    repo_root=repo_root,
                    capability_id=spec.capability_id,
                    probe_id=f"sample-{index}",
                    tool_path=tool_path,
                    actual_args=actual_args,
                    rendered_args=rendered_args,
                    timeout_seconds=timeout_seconds,
                    max_excerpt_chars=max_excerpt_chars,
                )
            )

    failing = [probe for probe in probes if probe["status"] != PROBE_STATUS_PASS]
    selected = failing[0] if failing else probes[-1]
    return {
        "capability_id": spec.capability_id,
        "tool_path": tool_display,
        "status": STATUS_PRESENT_FAIL if failing else STATUS_PRESENT_PASS,
        "command": selected["command"],
        "exit_code": selected["exit_code"],
        "stdout_excerpt": selected["stdout_excerpt"],
        "stderr_excerpt": selected["stderr_excerpt"],
        "source_refs": source_refs,
        "probes": probes,
    }


def build_report(
    repo_root: Path = REPO_ROOT,
    *,
    specs: Iterable[CapabilitySpec] = DEFAULT_CAPABILITIES,
    only: Iterable[str] = (),
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_excerpt_chars: int = DEFAULT_MAX_EXCERPT_CHARS,
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve()
    only_ids = {item.upper() for item in only}
    selected_specs = [spec for spec in specs if not only_ids or spec.capability_id.upper() in only_ids]
    capabilities = [
        smoke_capability(
            repo_root,
            spec,
            timeout_seconds=timeout_seconds,
            max_excerpt_chars=max_excerpt_chars,
        )
        for spec in selected_specs
    ]

    counts = {
        STATUS_PRESENT_PASS: sum(1 for row in capabilities if row["status"] == STATUS_PRESENT_PASS),
        STATUS_PRESENT_FAIL: sum(1 for row in capabilities if row["status"] == STATUS_PRESENT_FAIL),
        STATUS_PENDING: sum(1 for row in capabilities if row["status"] == STATUS_PENDING),
    }
    return {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "summary": {
            "capabilities": len(capabilities),
            "present_pass": counts[STATUS_PRESENT_PASS],
            "present_fail": counts[STATUS_PRESENT_FAIL],
            "pending": counts[STATUS_PENDING],
            "failing_capabilities": [
                row["capability_id"] for row in capabilities if row["status"] == STATUS_PRESENT_FAIL
            ],
            "pending_capabilities": [row["capability_id"] for row in capabilities if row["status"] == STATUS_PENDING],
        },
        "bounds": {
            "timeout_seconds": timeout_seconds,
            "max_excerpt_chars": max_excerpt_chars,
            "max_sample_probes_per_capability": MAX_SAMPLE_PROBES_PER_CAPABILITY,
        },
        "capabilities": capabilities,
        "assumptions": [
        "Missing Phase II standalone tool paths are expected during parallel buildout and are marked pending.",
        "Existing tools are probed with --help; configured sample JSON/JSONL paths are exercised only when present.",
        "SMIV includes a live-target report smoke probe against a local workspace fixture to exercise the canonical invocation path.",
    ],
}


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phase II Capability Smoke Report",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Tool: `{report['tool']}`",
        f"- Capabilities: {report['summary']['capabilities']}",
        f"- Present pass: {report['summary']['present_pass']}",
        f"- Present fail: {report['summary']['present_fail']}",
        f"- Pending: {report['summary']['pending']}",
        "",
        "| Capability | Status | Tool path | Exit code | Command |",
        "|---|---:|---|---:|---|",
    ]
    for row in report["capabilities"]:
        exit_code = "" if row["exit_code"] is None else str(row["exit_code"])
        command = row["command"].replace("|", "\\|")
        lines.append(
            f"| `{row['capability_id']}` | `{row['status']}` | `{row['tool_path']}` | {exit_code} | `{command}` |"
        )

    lines.extend(["", "## Probe Details", ""])
    for row in report["capabilities"]:
        lines.append(f"### {row['capability_id']}")
        lines.append("")
        lines.append(f"- Status: `{row['status']}`")
        lines.append(f"- Tool path: `{row['tool_path']}`")
        if row["source_refs"]:
            lines.append("- Source refs:")
            for ref in row["source_refs"]:
                lines.append(f"  - `{ref}`")
        if not row["probes"]:
            lines.append(f"- Pending reason: {row['stderr_excerpt']}")
            lines.append("")
            continue
        lines.append("- Probes:")
        for probe in row["probes"]:
            exit_code = "" if probe["exit_code"] is None else str(probe["exit_code"])
            lines.append(
                f"  - `{probe['probe_id']}` `{probe['status']}` exit `{exit_code}`: `{probe['command']}`"
            )
        if row["stdout_excerpt"]:
            lines.append("- Stdout excerpt:")
            lines.append("```")
            lines.append(row["stdout_excerpt"].rstrip())
            lines.append("```")
        if row["stderr_excerpt"]:
            lines.append("- Stderr excerpt:")
            lines.append("```")
            lines.append(row["stderr_excerpt"].rstrip())
            lines.append("```")
        lines.append("")

    if report.get("assumptions"):
        lines.append("## Assumptions")
        lines.append("")
        for item in report["assumptions"]:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _parse_key_path(token: str, flag: str) -> tuple[str, str]:
    if "=" not in token:
        raise SystemExit(f"{flag} requires CAPABILITY=path, got: {token}")
    key, value = token.split("=", 1)
    key = key.strip().upper()
    value = value.strip()
    if not key or not value:
        raise SystemExit(f"{flag} requires non-empty CAPABILITY=path, got: {token}")
    return key, value


def apply_cli_overrides(
    specs: Iterable[CapabilitySpec],
    *,
    tool_overrides: Iterable[str],
    sample_overrides: Iterable[str],
) -> tuple[CapabilitySpec, ...]:
    by_id = {spec.capability_id.upper(): spec for spec in specs}
    order = [spec.capability_id.upper() for spec in specs]

    for token in tool_overrides:
        key, path = _parse_key_path(token, "--tool")
        if key in by_id:
            by_id[key] = replace(by_id[key], tool_candidates=(path,))
        else:
            by_id[key] = CapabilitySpec(
                capability_id=key,
                tool_candidates=(path,),
                source_refs=("cli:--tool",),
                sample_arg_template=("--input", "{sample_path}"),
            )
            order.append(key)

    for token in sample_overrides:
        key, path = _parse_key_path(token, "--sample-json")
        if key not in by_id:
            by_id[key] = CapabilitySpec(
                capability_id=key,
                tool_candidates=(f"tools/{key.lower()}.py",),
                source_refs=("cli:--sample-json",),
                sample_arg_template=("--input", "{sample_path}"),
            )
            order.append(key)
        spec = by_id[key]
        by_id[key] = replace(spec, sample_path_candidates=(path, *spec.sample_path_candidates))

    return tuple(by_id[key] for key in order)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="repository root to probe")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--out", type=Path, help="optional report output path")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="seconds per probe")
    parser.add_argument("--max-excerpt-chars", type=int, default=DEFAULT_MAX_EXCERPT_CHARS)
    parser.add_argument("--only", action="append", default=[], help="capability id to include; repeatable")
    parser.add_argument("--tool", action="append", default=[], help="override/add tool path as CAPABILITY=path")
    parser.add_argument("--sample-json", action="append", default=[], help="add sample JSON/JSONL path as CAPABILITY=path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    specs = apply_cli_overrides(
        DEFAULT_CAPABILITIES,
        tool_overrides=args.tool,
        sample_overrides=args.sample_json,
    )
    report = build_report(
        args.repo_root,
        specs=specs,
        only=args.only,
        timeout_seconds=max(0.1, args.timeout),
        max_excerpt_chars=max(80, args.max_excerpt_chars),
    )
    rendered = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else render_markdown(report)
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
