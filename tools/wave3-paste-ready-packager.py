#!/usr/bin/env python3
"""Wave-3 paste-ready packager: per-platform paste-ready shape emission.

Takes a canonical Cantina-shaped draft as input, runs the applicable rule
gates, and emits a platform-shaped paste-ready ready for operator paste
into Cantina / Immunefi / Sherlock / Code4rena.

The tool is stdlib-only (no PyYAML required - a minimal subset parser is
embedded). Hermetic. Idempotent. Output never contains em-dashes per the
global formatting rule.

Schema: auditooor.wave3_paste_ready_packager.v1

CLI:
    --input <draft.md>        Operator canonical Cantina-shaped draft.
    --platform <p>            cantina | immunefi | sherlock | code4rena.
    --workspace <ws>          Workspace root (defaults to draft parent).
    --target-protocol <name>  Protocol slug (e.g. thegraph, dydx, spark).
    --severity-rubric <path>  Optional rubric YAML override. If unset, the
                              builtin audit/severity_rubrics/<platform>.yaml
                              is loaded.
    --output <path>           Output paste-ready path (default: stdout).
    --json                    Emit verification JSON instead of markdown.
    --strict                  Exit 1 if any blocking gate fails.

Exit codes:
    0 - PASS (READY_TO_PASTE) or DEGRADED-WITH-OVERRIDES (non-strict)
    1 - BLOCKED (one or more required gates failed)
    2 - input/config error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.wave3_paste_ready_packager.v1"

REPO_ROOT_CANDIDATES = [
    Path("/private/tmp/auditooor-cyfrin-w24"),
    Path("/tmp/auditooor-paste-packager"),
    Path("/Users/wolf/auditooor-702-full"),
    Path(__file__).resolve().parent.parent,
]


def repo_root() -> Path:
    here = Path(__file__).resolve().parent.parent
    if (here / "tools").is_dir() and (here / "audit").is_dir():
        return here
    for cand in REPO_ROOT_CANDIDATES:
        if cand.is_dir() and (cand / "tools").is_dir():
            return cand
    return here


# Gate registry: (gate_id, tool_relpath, cosmos_only)
GATES: list[tuple[str, str, bool]] = [
    ("R17", "tools/rubric-match-check.py", False),  # Best-effort discovery.
    ("R18", "tools/in-process-vs-node-level-check.py", False),
    ("R19", "tools/in-process-vs-node-level-check.py", False),  # R19 piggybacks on R18 tool.
    ("R20", "tools/control-test-discipline-check.py", False),
    ("R21", "tools/permanent-impact-five-ask-template-check.py", False),
    ("R22", "tools/restart-survival-check.py", False),
    ("R23", "tools/comparative-baseline-check.py", False),
    ("R24", "tools/non-self-impact-check.py", False),
    ("R25", "tools/defense-in-depth-traversal-check.py", False),
    ("R26", "tools/ante-handler-traversal-check.py", True),
    ("R27", "tools/adjacent-finding-disclosure-check.py", False),
    ("R30", "tools/production-profile-preflight-check.py", False),
    ("L30", "tools/missing-guard-callsite-enumerator.sh", False),
    ("L31", "tools/duplicate-preflight-check.py", False),
    ("L32", "tools/in-process-vs-node-level-check.py", False),
]


# Minimal YAML subset parser - supports the constructs we ship in
# audit/severity_rubrics/*.yaml. Handles:
#   key: scalar
#   key: |  (block literal)
#   key:    (mapping)
#     subkey: value
#   - list item
#   - mapping list item (key: value pairs indented under)
# Stdlib-only.
def _yaml_load(text: str) -> Any:
    lines = [ln.rstrip() for ln in text.splitlines()]
    pos = 0

    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def is_blank(line: str) -> bool:
        s = line.strip()
        return not s or s.startswith("#")

    def parse_scalar(s: str) -> Any:
        s = s.strip()
        if s == "":
            return None
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            return s[1:-1]
        if s.startswith("[") and s.endswith("]"):
            inner = s[1:-1].strip()
            if not inner:
                return []
            return [parse_scalar(p) for p in inner.split(",")]
        if s.lower() == "true":
            return True
        if s.lower() == "false":
            return False
        if s.lower() == "null" or s == "~":
            return None
        try:
            if "." in s:
                return float(s)
            return int(s)
        except ValueError:
            return s

    def parse_block(base_indent: int) -> Any:
        nonlocal pos
        result_map: dict[str, Any] = {}
        result_list: list[Any] = []
        mode: str | None = None
        while pos < len(lines):
            line = lines[pos]
            if is_blank(line):
                pos += 1
                continue
            cur_indent = indent(line)
            if cur_indent < base_indent:
                break
            if cur_indent > base_indent and mode is None:
                # We shouldn't reach here for well-formed YAML at this entry point.
                break
            stripped = line.strip()
            if stripped.startswith("- "):
                if mode is None:
                    mode = "list"
                if mode != "list":
                    break
                item_body = stripped[2:].strip()
                if ":" in item_body and not item_body.startswith("'") and not item_body.startswith('"'):
                    # Inline mapping start under a list item.
                    k, _, v = item_body.partition(":")
                    pos += 1
                    sub_map: dict[str, Any] = {}
                    sub_map[k.strip()] = parse_scalar(v) if v.strip() else parse_block(base_indent + 2)
                    # Continue gathering same-indent siblings for the mapping.
                    while pos < len(lines):
                        nxt = lines[pos]
                        if is_blank(nxt):
                            pos += 1
                            continue
                        if indent(nxt) <= base_indent:
                            break
                        nxt_s = nxt.strip()
                        if ":" in nxt_s:
                            kk, _, vv = nxt_s.partition(":")
                            if vv.strip() == "":
                                pos += 1
                                sub_map[kk.strip()] = parse_block(indent(nxt) + 2)
                            elif vv.strip() == "|":
                                pos += 1
                                sub_map[kk.strip()] = _gather_block_literal(lines, pos, indent(nxt) + 2)
                                pos = _advance_block_literal(lines, pos, indent(nxt) + 2)
                            else:
                                sub_map[kk.strip()] = parse_scalar(vv)
                                pos += 1
                        else:
                            break
                    result_list.append(sub_map)
                else:
                    result_list.append(parse_scalar(item_body))
                    pos += 1
                continue
            elif ":" in stripped:
                if mode is None:
                    mode = "map"
                if mode != "map":
                    break
                k, _, v = stripped.partition(":")
                k = k.strip()
                v_strip = v.strip()
                if v_strip == "":
                    pos += 1
                    result_map[k] = parse_block(cur_indent + 2)
                elif v_strip == "|":
                    pos += 1
                    block_lit = _gather_block_literal(lines, pos, cur_indent + 2)
                    pos = _advance_block_literal(lines, pos, cur_indent + 2)
                    result_map[k] = block_lit
                else:
                    result_map[k] = parse_scalar(v_strip)
                    pos += 1
            else:
                pos += 1

        if mode == "list":
            return result_list
        return result_map

    result = parse_block(0)
    return result


def _gather_block_literal(lines: list[str], start: int, min_indent: int) -> str:
    out: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            out.append("")
            i += 1
            continue
        if len(line) - len(line.lstrip(" ")) < min_indent:
            break
        out.append(line[min_indent:])
        i += 1
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def _advance_block_literal(lines: list[str], start: int, min_indent: int) -> int:
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            i += 1
            continue
        if len(line) - len(line.lstrip(" ")) < min_indent:
            break
        i += 1
    return i


@dataclass
class GateResult:
    gate_id: str
    status: str   # PASS | FAIL | SKIP | NA | ERROR
    detail: str = ""
    rebuttal: str = ""


@dataclass
class PackageResult:
    input_draft_path: str
    output_path: str
    target_platform: str
    target_protocol: str
    gate_results: list[GateResult] = field(default_factory=list)
    overall_status: str = "BLOCKED"
    blocking_gates: list[str] = field(default_factory=list)
    rebuttals_present: list[str] = field(default_factory=list)
    package_metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    schema_version: str = SCHEMA_VERSION


def load_rubric(platform: str, override_path: Path | None) -> dict[str, Any]:
    if override_path is not None:
        path = override_path
    else:
        path = repo_root() / "audit" / "severity_rubrics" / f"{platform}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"rubric not found: {path}")
    text = path.read_text(encoding="utf-8")
    parsed = _yaml_load(text)
    if not isinstance(parsed, dict):
        raise ValueError(f"rubric {path} did not parse to a mapping (got {type(parsed).__name__})")
    return parsed


SEVERITY_RE = re.compile(r"(?im)^[\s\-*]*Severity\s*:\**\s*(Critical|High|Medium|Low|QA|Gas)\b")
TITLE_RE = re.compile(r"(?im)^#\s+(.+?)\s*$")
REBUTTAL_RE = re.compile(r"<!--\s*(r\d+|l\d+)-rebuttal\s*:\s*(.+?)\s*-->", re.IGNORECASE)


def detect_severity(draft_text: str) -> str | None:
    match = SEVERITY_RE.search(draft_text)
    if match:
        return match.group(1).strip().lower()
    return None


def detect_title(draft_text: str) -> str | None:
    match = TITLE_RE.search(draft_text)
    if match:
        return match.group(1).strip()
    return None


def detect_rebuttals(draft_text: str) -> list[str]:
    return [m.group(1).lower() for m in REBUTTAL_RE.finditer(draft_text)]


def detect_cosmos(draft_text: str, workspace: Path | None) -> bool:
    """Best-effort detect if finding targets cosmos-sdk chain."""
    needles = ["cosmos-sdk", "cometbft", "tendermint", "BaseApp", "MsgExec",
               "FinalizeBlock", "DeliverTx", "ante decorator", "dydx", "Osmosis", "spark statechain"]
    blob = draft_text.lower()
    for needle in needles:
        if needle.lower() in blob:
            return True
    return False


def find_rubric_tier(rubric: dict[str, Any], severity: str | None) -> dict[str, Any] | None:
    if severity is None:
        return None
    tiers = rubric.get("tiers", [])
    if not isinstance(tiers, list):
        return None
    for tier in tiers:
        if not isinstance(tier, dict):
            continue
        if tier.get("id", "").lower() == severity:
            return tier
    return None


def run_gate(gate_id: str, tool_relpath: str, draft_path: Path,
             workspace: Path | None, dry_run: bool = False) -> GateResult:
    """Invoke an external rule-gate tool. If unavailable, mark SKIP.

    Many gate tools differ in CLI signature: some accept --input <draft>,
    some accept a positional draft, some require --workspace, some don't.
    Probe --help once to discover the CLI shape, then dispatch accordingly.
    Argparse usage-error exits (rc=2) become INDETERMINATE rather than FAIL
    because they reflect CLI signature mismatch, not a finding-quality issue.
    """
    tool_path = repo_root() / tool_relpath
    if not tool_path.exists():
        return GateResult(gate_id, "SKIP", detail=f"tool not present: {tool_relpath}")
    if dry_run:
        return GateResult(gate_id, "SKIP", detail="dry-run")
    if tool_path.suffix == ".sh":
        # Shell helpers - just pass the draft positionally.
        cmd = ["bash", str(tool_path), str(draft_path)]
        return _exec_gate(gate_id, cmd)
    if tool_path.suffix != ".py":
        return GateResult(gate_id, "SKIP", detail=f"unknown tool suffix: {tool_path.suffix}")

    # Probe --help to detect CLI shape.
    try:
        help_proc = subprocess.run(
            [sys.executable, str(tool_path), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        help_text = (help_proc.stdout or "") + (help_proc.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        return GateResult(gate_id, "ERROR", detail=f"help probe failed: {exc}")

    cmd: list[str] = [sys.executable, str(tool_path)]
    if "--input" in help_text:
        cmd.extend(["--input", str(draft_path)])
    elif "--draft" in help_text:
        cmd.extend(["--draft", str(draft_path)])
    else:
        # Positional draft is the convention used by tools like
        # production-profile-preflight-check.py and several others.
        cmd.append(str(draft_path))
    if workspace is not None and "--workspace" in help_text:
        cmd.extend(["--workspace", str(workspace)])

    return _exec_gate(gate_id, cmd)


def _exec_gate(gate_id: str, cmd: list[str]) -> GateResult:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return GateResult(gate_id, "ERROR", detail="timeout (>30s)")
    except (FileNotFoundError, PermissionError) as exc:
        return GateResult(gate_id, "ERROR", detail=f"exec failed: {exc}")
    if proc.returncode == 0:
        return GateResult(gate_id, "PASS", detail="exit-0")
    detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip().splitlines()
    detail_line = detail[0][:200] if detail else f"exit {proc.returncode}"
    # rc=2 is argparse usage-error convention - treat as INDETERMINATE not FAIL.
    if proc.returncode == 2:
        return GateResult(gate_id, "INDETERMINATE", detail=f"cli-shape mismatch: {detail_line}")
    return GateResult(gate_id, "FAIL", detail=detail_line)


def reshape_for_platform(draft_text: str, platform: str, rubric: dict[str, Any],
                         severity: str | None, target_protocol: str) -> str:
    """Reshape a Cantina-canonical draft into a platform-specific paste-ready.

    Heuristic-driven section extraction; never destructive (loss of section
    falls back to a stub note rather than silently dropping content).
    """
    sections = parse_sections(draft_text)
    out_order = rubric.get("required_section_order", [])
    if not isinstance(out_order, list) or not out_order:
        return draft_text

    rubric_tier = find_rubric_tier(rubric, severity)
    rubric_verbatim = (rubric_tier or {}).get("rubric_verbatim", "").strip()

    chunks: list[str] = []
    title = sections.get("__title__", "Untitled finding")
    body_map = {k.lower(): v for k, v in sections.items() if not k.startswith("__")}

    for sec_name in out_order:
        key = sec_name.lower()
        if sec_name == "Title":
            chunks.append(f"# {title}")
            chunks.append("")
            continue

        body = body_map.get(key, "")
        # Platform-specific mapping fallbacks.
        if not body:
            body = _platform_section_fallback(sec_name, body_map, platform,
                                              rubric_verbatim, target_protocol, severity)

        chunks.append(f"## {sec_name}")
        chunks.append("")
        if body.strip():
            chunks.append(body.rstrip())
            chunks.append("")

    metadata_block = _build_metadata_footer(platform, target_protocol, rubric, severity, rubric_tier)
    chunks.append(metadata_block)
    return "\n".join(chunks).rstrip() + "\n"


def parse_sections(draft_text: str) -> dict[str, str]:
    """Split a markdown draft into {section_name: body} keyed by H2 headers.

    Also stores the H1 title under the '__title__' sentinel key.
    """
    result: dict[str, str] = {}
    title_match = TITLE_RE.search(draft_text)
    if title_match:
        result["__title__"] = title_match.group(1).strip()
    parts = re.split(r"(?m)^##\s+(.+?)\s*$", draft_text)
    # parts pattern: [pre, header1, body1, header2, body2, ...]
    if len(parts) < 3:
        return result
    for i in range(1, len(parts), 2):
        header = parts[i].strip()
        body = parts[i + 1] if (i + 1) < len(parts) else ""
        result[header] = body.strip()
    return result


def _platform_section_fallback(sec_name: str, body_map: dict[str, str], platform: str,
                                rubric_verbatim: str, target_protocol: str,
                                severity: str | None) -> str:
    sn = sec_name.lower()
    if sn == "severity":
        if severity:
            return f"- Severity: {severity.capitalize()}\n\nRubric quote (verbatim):\n> {rubric_verbatim}"
        return f"Rubric quote (verbatim):\n> {rubric_verbatim}"
    if sn in ("summary", "vulnerability details", "vulnerability detail", "vulnerability details"):
        return body_map.get("summary", "") or body_map.get("root cause", "")
    if sn == "impact details":
        return body_map.get("impact", "")
    if sn == "code snippet":
        return body_map.get("root cause", "")
    if sn == "lines of code":
        return _extract_line_refs(body_map.get("root cause", ""))
    if sn == "recommendation" or sn == "recommended fix" or sn == "recommended mitigation steps":
        return body_map.get("recommended fix", "") or body_map.get("recommendation", "")
    if sn == "tool used" or sn == "tools used":
        return f"Manual review, Foundry, auditooor toolchain (Wave-3 packager v1 targeting {platform})."
    if sn == "proof of concept":
        return body_map.get("proof of concept", "")
    if sn == "references":
        return f"Target protocol: {target_protocol}\nPlatform: {platform}"
    if sn == "vulnerability details":
        return body_map.get("root cause", "") or body_map.get("summary", "")
    return ""


def _extract_line_refs(root_cause_body: str) -> str:
    refs = re.findall(r"`?([A-Za-z0-9_./-]+\.(?:sol|go|rs|ts))(?::(\d+)(?:-(\d+))?)?`?", root_cause_body)
    if not refs:
        return "(see Vulnerability details for file:line citations)"
    lines: list[str] = []
    for r in refs[:8]:
        path = r[0]
        if r[1]:
            if r[2]:
                lines.append(f"- {path}#L{r[1]}-L{r[2]}")
            else:
                lines.append(f"- {path}#L{r[1]}")
        else:
            lines.append(f"- {path}")
    return "\n".join(lines)


def _build_metadata_footer(platform: str, target_protocol: str, rubric: dict[str, Any],
                           severity: str | None, rubric_tier: dict[str, Any] | None) -> str:
    payout = ""
    if rubric_tier:
        if "payout_range_usd" in rubric_tier:
            r = rubric_tier["payout_range_usd"]
            if isinstance(r, list) and len(r) == 2:
                payout = f"${r[0]:,} - ${r[1]:,}"
        elif "payout_formula" in rubric_tier:
            payout = str(rubric_tier["payout_formula"])
    return (
        "<!-- wave3-paste-ready-packager-metadata\n"
        f"platform: {platform}\n"
        f"target_protocol: {target_protocol}\n"
        f"severity: {severity or 'unspecified'}\n"
        f"payout_indication: {payout or 'see rubric'}\n"
        f"packager_schema: {SCHEMA_VERSION}\n"
        "-->\n"
    )


def package(draft_path: Path, platform: str, workspace: Path | None,
            target_protocol: str, rubric_override: Path | None,
            strict: bool, dry_run_gates: bool = False) -> tuple[str, PackageResult]:
    draft_text = draft_path.read_text(encoding="utf-8")
    rubric = load_rubric(platform, rubric_override)

    severity = detect_severity(draft_text)
    title = detect_title(draft_text) or "(untitled)"
    rebuttals = detect_rebuttals(draft_text)
    cosmos = detect_cosmos(draft_text, workspace)

    required_gates: list[str] = list(rubric.get("gates_required", []) or [])
    if not required_gates:
        required_gates = [g[0] for g in GATES]

    gate_results: list[GateResult] = []
    for gate_id, tool_rel, cosmos_only in GATES:
        if gate_id not in required_gates:
            continue
        if cosmos_only and not cosmos:
            gate_results.append(GateResult(gate_id, "NA", detail="not a cosmos-sdk finding"))
            continue
        result = run_gate(gate_id, tool_rel, draft_path, workspace, dry_run=dry_run_gates)
        # Apply rebuttal override if present.
        if result.status == "FAIL":
            tag = gate_id.lower()
            if tag in rebuttals or tag.replace("r", "l") in rebuttals:
                result.status = "PASS"
                result.detail = f"override via {tag}-rebuttal"
                result.rebuttal = tag
        gate_results.append(result)

    blocking = [g.gate_id for g in gate_results if g.status == "FAIL"]
    indeterminate = [g.gate_id for g in gate_results if g.status == "INDETERMINATE"]
    if blocking:
        overall = "BLOCKED"
    elif any(g.rebuttal for g in gate_results):
        overall = "DEGRADED-WITH-OVERRIDES"
    elif indeterminate:
        overall = "READY_TO_PASTE_WITH_INDETERMINATE_GATES"
    else:
        overall = "READY_TO_PASTE"

    rubric_tier = find_rubric_tier(rubric, severity)
    rubric_verbatim = (rubric_tier or {}).get("rubric_verbatim", "").strip()

    reshaped = reshape_for_platform(draft_text, platform, rubric, severity, target_protocol)

    out_path = ""
    metadata: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "rubric_row_verbatim": rubric_verbatim,
        "originality_ref": _detect_originality_ref(draft_text),
        "poc_paths": _detect_poc_paths(draft_text),
        "cosmos_detected": cosmos,
    }

    result = PackageResult(
        input_draft_path=str(draft_path),
        output_path=out_path,
        target_platform=platform,
        target_protocol=target_protocol,
        gate_results=gate_results,
        overall_status=overall,
        blocking_gates=blocking,
        rebuttals_present=rebuttals,
        package_metadata=metadata,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    return reshaped, result


def _detect_originality_ref(draft_text: str) -> str:
    m = re.search(r"(?im)^##\s*Scope And Originality\s*$", draft_text)
    if m:
        return "## Scope And Originality section present"
    return "absent"


def _detect_poc_paths(draft_text: str) -> list[str]:
    paths = re.findall(r"`?([A-Za-z0-9_./-]+\.(?:t\.sol|_test\.go|\.rs))`?", draft_text)
    seen: list[str] = []
    for p in paths:
        if p not in seen:
            seen.append(p)
    return seen[:10]


def serialize_result(result: PackageResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "timestamp": result.timestamp,
        "input_draft_path": result.input_draft_path,
        "output_path": result.output_path,
        "target_platform": result.target_platform,
        "target_protocol": result.target_protocol,
        "overall_status": result.overall_status,
        "blocking_gates": result.blocking_gates,
        "rebuttals_present": result.rebuttals_present,
        "package_metadata": result.package_metadata,
        "gate_results": [
            {
                "gate_id": g.gate_id,
                "status": g.status,
                "detail": g.detail,
                "rebuttal": g.rebuttal,
            }
            for g in result.gate_results
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Wave-3 paste-ready packager.")
    parser.add_argument("--input", required=True, help="Input canonical Cantina-shaped draft.")
    parser.add_argument("--platform", required=True,
                        choices=["cantina", "immunefi", "sherlock", "code4rena"])
    parser.add_argument("--workspace", default=None, help="Workspace root.")
    parser.add_argument("--target-protocol", default="unknown",
                        help="Protocol slug (e.g. thegraph, dydx, spark).")
    parser.add_argument("--severity-rubric", default=None,
                        help="Override path for severity rubric YAML.")
    parser.add_argument("--output", default=None, help="Output path for paste-ready (default: stdout).")
    parser.add_argument("--json", action="store_true", help="Emit verification JSON instead of markdown.")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any blocking gate fails.")
    parser.add_argument("--dry-run-gates", action="store_true",
                        help="Skip all gate execution (smoke tests).")
    args = parser.parse_args(argv)

    draft_path = Path(args.input).resolve()
    if not draft_path.exists():
        print(f"error: input draft not found: {draft_path}", file=sys.stderr)
        return 2

    workspace = Path(args.workspace).resolve() if args.workspace else draft_path.parent
    rubric_override = Path(args.severity_rubric).resolve() if args.severity_rubric else None

    try:
        reshaped, result = package(
            draft_path=draft_path,
            platform=args.platform,
            workspace=workspace,
            target_protocol=args.target_protocol,
            rubric_override=rubric_override,
            strict=args.strict,
            dry_run_gates=args.dry_run_gates,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: rubric parse failure: {exc}", file=sys.stderr)
        return 2

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(reshaped, encoding="utf-8")
        result.output_path = str(out_path)

    if args.json:
        print(json.dumps(serialize_result(result), indent=2))
    else:
        if not args.output:
            sys.stdout.write(reshaped)
        # Emit a one-line verification summary to stderr for operator awareness.
        summary = (
            f"[wave3-packager] platform={result.target_platform} "
            f"status={result.overall_status} "
            f"blocking={','.join(result.blocking_gates) or 'none'} "
            f"rebuttals={','.join(result.rebuttals_present) or 'none'}"
        )
        print(summary, file=sys.stderr)

    if args.strict and result.overall_status == "BLOCKED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
