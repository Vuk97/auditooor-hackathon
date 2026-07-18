#!/usr/bin/env python3
"""Map V3 audit workflow concept coverage from Makefile wiring.

This is an offline inspection helper. It reads the Makefile, selected workflow
tool entrypoints, and tool filenames; it does not execute make targets or
providers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAKEFILE = REPO_ROOT / "Makefile"
DEFAULT_TOOLS_DIR = REPO_ROOT / "tools"

WORKFLOW_ORDER = ("audit", "audit_deep", "closeout", "pre_submit")
EVIDENCE_LIMIT = 4
TOOL_EVIDENCE_LIMIT = 5


@dataclass(frozen=True)
class Concept:
    concept_id: str
    label: str
    patterns: tuple[str, ...]


CONCEPTS: tuple[Concept, ...] = (
    Concept(
        "mcp_recall",
        "MCP recall",
        (
            r"\bMCP\b",
            r"\bmcp[-_ ]",
            r"\brecall\b",
            r"vault[-_]mcp",
            r"memory[-_]context",
            r"memory_context_receipt",
            r"agent[-_]recall",
        ),
    ),
    Concept(
        "hacker_questions",
        "Hacker questions",
        (
            r"hacker[-_ ]question",
            r"hacker_question",
            r"HACKER-QUESTION",
            r"question[-_ ]obligation",
        ),
    ),
    Concept(
        "brain_prime_hacker_brief",
        "Brain prime / hacker brief",
        (
            r"brain[-_]prime",
            r"hacker[-_]brief",
            r"hacker_brief",
            r"agent[-_]prompt[-_]hacker[-_]augmenter",
            r"hackerman[-_]brief",
        ),
    ),
    Concept(
        "provider_fanout",
        "Provider fanout",
        (
            r"provider[-_]fanout",
            r"\bv3[-_]provider",
            r"\bfanout\b",
        ),
    ),
    Concept(
        "oos_scope",
        "OOS / scope",
        (
            r"\bOOS\b",
            r"\boos[-_]",
            r"\bscope\b",
            r"scope[-_]reasoner",
            r"per[-_]finding[-_]oos",
            r"extract[-_]oos",
        ),
    ),
    Concept(
        "originality",
        "Originality",
        (
            r"\boriginality\b",
            r"prior[-_]disclosure",
            r"published[-_]source",
            r"before[-_]proof",
        ),
    ),
    Concept(
        "dupe_risk",
        "Dupe risk",
        (
            r"\bdupe[-_ ]",
            r"\bduplicate\b",
            r"dupe[-_]risk",
            r"duplicate[-_]risk",
        ),
    ),
    Concept(
        "candidate_judgment",
        "Candidate judgment",
        (
            r"candidate[-_ ]judgment",
            r"judgment[-_ ]packet",
            r"prefiling[-_ ]stress",
            r"severity[-_ ]scope[-_ ]oracle",
            r"originality[-_ ]before[-_ ]proof",
        ),
    ),
    Concept(
        "severity_calibration",
        "Severity calibration",
        (
            r"severity[-_ ]calibration",
            r"severity[-_]calibration[-_](?:check|gate)",
            r"SEVERITY-CALIBRATION",
            r"severity[-_ ]claim[-_ ]guard",
            r"high[-_]plus[-_]submission[-_]gate",
        ),
    ),
    Concept(
        "proof_execution",
        "Proof execution",
        (
            r"\bPoC\b",
            r"\bpoc[-_]",
            r"\bexecution\b",
            r"\bharness\b",
            r"fork[-_]replay",
            r"halmos",
            r"medusa",
            r"echidna",
            r"high[-_]impact[-_]execution[-_]bridge",
            r"live[-_]topology",
        ),
    ),
    Concept(
        "queue_closeout",
        "Queue closeout",
        (
            r"\bqueue\b",
            r"\bcloseout\b",
            r"close[-_]out",
            r"completion[-_]marker",
            r"finalization",
            r"exploit[-_]conversion[-_]loop",
        ),
    ),
    Concept(
        "external_intel_mining",
        "External intel mining",
        (
            r"external[-_]intel",
            r"external[-_]recall",
            r"prior[-_]disclosure",
            r"source[-_]mine",
            r"source[-_]miner",
            r"git[-_]commits[-_]mining",
            r"hackerman[-_]etl",
            r"post[-_]mortem",
            r"solodit",
            r"audit[-_]firm",
        ),
    ),
    Concept(
        "agent_artifact_mining",
        "Agent artifact mining",
        (
            r"agent[-_]artifact",
            r"agent_artifact",
            r"agent[-_]learning",
            r"artifact[-_]miner",
        ),
    ),
)


@dataclass(frozen=True)
class Line:
    path: Path
    number: int
    text: str


@dataclass(frozen=True)
class WorkflowSource:
    workflow_id: str
    label: str
    lines: tuple[Line, ...]
    source_refs: tuple[str, ...]


def _compile(patterns: Iterable[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _is_target_header(line: str) -> bool:
    if not line or line.startswith(("\t", " ", "#", ".")):
        return False
    if ":=" in line or "?=" in line or "+=" in line or "=" in line.split(":", 1)[0]:
        return False
    return re.match(r"^[A-Za-z0-9_.%/@$() -]+:(?:\s|$)", line) is not None


def parse_makefile_targets(makefile: Path) -> dict[str, tuple[Line, ...]]:
    lines = makefile.read_text(encoding="utf-8").splitlines()
    targets: dict[str, list[Line]] = {}
    current_names: list[str] = []
    current: list[Line] = []

    def flush() -> None:
        if not current_names:
            return
        block = tuple(current)
        for name in current_names:
            targets[name] = block

    for number, text in enumerate(lines, 1):
        if _is_target_header(text):
            flush()
            header = text.split(":", 1)[0]
            current_names = [part for part in header.split() if part]
            current = [Line(makefile, number, text)]
        elif current_names and text.startswith("\t"):
            current.append(Line(makefile, number, text))
    flush()
    return targets


def _makefile_reference_lines(makefile: Path, pattern: re.Pattern[str]) -> tuple[Line, ...]:
    refs: list[Line] = []
    for number, text in enumerate(makefile.read_text(encoding="utf-8").splitlines(), 1):
        if pattern.search(text):
            refs.append(Line(makefile, number, text))
    return tuple(refs)


def build_workflow_sources(makefile: Path, tools_dir: Path) -> dict[str, WorkflowSource]:
    targets = parse_makefile_targets(makefile)
    closeout_target_names = (
        "audit-closeout",
        "audit-closeout-case-study",
        "v3-provider-fanout-closeout",
        "loop-finalization-check",
    )
    pre_submit_path = tools_dir / "pre-submit-check.sh"
    pre_submit_refs = _makefile_reference_lines(makefile, re.compile(r"pre[-_]submit[-_]check\.sh", re.IGNORECASE))

    pre_submit_lines: list[Line] = list(pre_submit_refs)
    if pre_submit_path.is_file():
        pre_submit_lines.extend(
            Line(pre_submit_path, number, text)
            for number, text in enumerate(pre_submit_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
        )

    workflows = {
        "audit": WorkflowSource(
            "audit",
            "make audit",
            targets.get("audit", ()),
            ("Makefile target: audit",),
        ),
        "audit_deep": WorkflowSource(
            "audit_deep",
            "make audit-deep",
            targets.get("audit-deep", ()),
            ("Makefile target: audit-deep",),
        ),
        "closeout": WorkflowSource(
            "closeout",
            "closeout",
            tuple(line for target in closeout_target_names for line in targets.get(target, ())),
            tuple(f"Makefile target: {target}" for target in closeout_target_names if target in targets),
        ),
        "pre_submit": WorkflowSource(
            "pre_submit",
            "pre-submit",
            tuple(pre_submit_lines),
            tuple(
                ref
                for ref in (
                    "Makefile references: pre-submit-check.sh" if pre_submit_refs else "",
                    f"tool: {pre_submit_path.relative_to(makefile.parent)}" if pre_submit_path.is_file() else "",
                )
                if ref
            ),
        ),
    }
    return workflows


def selected_tool_filename_evidence(tools_dir: Path) -> dict[str, list[dict[str, str]]]:
    evidence: dict[str, list[dict[str, str]]] = {concept.concept_id: [] for concept in CONCEPTS}
    if not tools_dir.is_dir():
        return evidence

    concept_patterns = {concept.concept_id: _compile(concept.patterns) for concept in CONCEPTS}
    skipped_parts = {"__pycache__", ".pytest_cache", "fixtures"}
    for path in sorted(tools_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(tools_dir.parent).as_posix()
        if any(part in skipped_parts for part in path.relative_to(tools_dir).parts):
            continue
        if "/tests/" in rel:
            continue
        for concept in CONCEPTS:
            rows = evidence[concept.concept_id]
            if len(rows) >= TOOL_EVIDENCE_LIMIT:
                continue
            if concept_patterns[concept.concept_id].search(rel):
                rows.append({"ref": rel, "snippet": "filename match"})
    return evidence


def _ref_for_line(line: Line, root: Path) -> str:
    try:
        rel = line.path.relative_to(root).as_posix()
    except ValueError:
        rel = line.path.as_posix()
    return f"{rel}:{line.number}"


def _line_evidence(lines: Iterable[Line], concept: Concept, root: Path) -> list[dict[str, str]]:
    pattern = _compile(concept.patterns)
    rows: list[dict[str, str]] = []
    for line in lines:
        if not pattern.search(line.text):
            continue
        snippet = " ".join(line.text.strip().split())
        rows.append({"ref": _ref_for_line(line, root), "snippet": snippet[:220]})
        if len(rows) >= EVIDENCE_LIMIT:
            break
    return rows


def build_report(makefile: Path, tools_dir: Path) -> dict[str, object]:
    makefile = makefile.resolve()
    tools_dir = tools_dir.resolve()
    root = makefile.parent
    workflows = build_workflow_sources(makefile, tools_dir)
    tool_evidence = selected_tool_filename_evidence(tools_dir)

    workflow_rows: list[dict[str, object]] = []
    summary = {
        concept.concept_id: {"label": concept.label, "present": 0, "unknown": 0, "missing": 0}
        for concept in CONCEPTS
    }

    for workflow_id in WORKFLOW_ORDER:
        source = workflows[workflow_id]
        concept_rows: list[dict[str, object]] = []
        for concept in CONCEPTS:
            direct = _line_evidence(source.lines, concept, root)
            supporting = tool_evidence.get(concept.concept_id, [])
            if direct:
                status = "present"
                evidence = direct
            elif supporting:
                status = "unknown"
                evidence = supporting[:EVIDENCE_LIMIT]
            else:
                status = "missing"
                evidence = []
            summary[concept.concept_id][status] += 1
            concept_rows.append(
                {
                    "concept_id": concept.concept_id,
                    "label": concept.label,
                    "status": status,
                    "evidence": evidence,
                }
            )
        workflow_rows.append(
            {
                "workflow_id": source.workflow_id,
                "label": source.label,
                "source_refs": source.source_refs,
                "concepts": concept_rows,
            }
        )

    return {
        "schema": "auditooor.audit_workflow_coverage_map.v1",
        "makefile": makefile.as_posix(),
        "tools_dir": tools_dir.as_posix(),
        "status_semantics": {
            "present": "workflow source contains matching wiring evidence",
            "unknown": "supporting tool filename exists, but this workflow source did not visibly invoke it",
            "missing": "no workflow wiring or supporting filename evidence was found",
        },
        "workflows": workflow_rows,
        "concept_summary": summary,
    }


def _status_for(report: dict[str, object], workflow_id: str, concept_id: str) -> str:
    for workflow in report["workflows"]:  # type: ignore[index]
        if workflow["workflow_id"] != workflow_id:
            continue
        for concept in workflow["concepts"]:
            if concept["concept_id"] == concept_id:
                return concept["status"]
    return "missing"


def render_markdown(report: dict[str, object]) -> str:
    concept_labels = {concept.concept_id: concept.label for concept in CONCEPTS}
    workflow_labels = {
        workflow["workflow_id"]: workflow["label"]
        for workflow in report["workflows"]  # type: ignore[index]
    }
    lines = [
        "# Audit Workflow Coverage Map",
        "",
        f"- Makefile: `{report['makefile']}`",
        f"- Tools dir: `{report['tools_dir']}`",
        "- Status: `present` = workflow wiring evidence; `unknown` = supporting tool exists but workflow link is not visible; `missing` = no evidence.",
        "",
        "## Matrix",
        "",
        "| Concept | make audit | make audit-deep | closeout | pre-submit |",
        "|---|---:|---:|---:|---:|",
    ]
    for concept_id, label in concept_labels.items():
        cells = [_status_for(report, workflow_id, concept_id) for workflow_id in WORKFLOW_ORDER]
        lines.append(f"| {label} | " + " | ".join(f"`{cell}`" for cell in cells) + " |")

    lines.extend(["", "## Evidence", ""])
    for workflow in report["workflows"]:  # type: ignore[index]
        lines.append(f"### {workflow_labels[workflow['workflow_id']]}")
        if workflow.get("source_refs"):
            refs = ", ".join(f"`{ref}`" for ref in workflow["source_refs"])
            lines.append(f"Sources: {refs}")
        for concept in workflow["concepts"]:
            evidence = concept["evidence"]
            if not evidence:
                lines.append(f"- {concept['label']}: `{concept['status']}`")
                continue
            refs = "; ".join(f"{row['ref']} `{row['snippet']}`" for row in evidence)
            lines.append(f"- {concept['label']}: `{concept['status']}` - {refs}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--makefile", type=Path, default=DEFAULT_MAKEFILE)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--out", type=Path, help="optional output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.makefile.is_file():
        print(f"[audit-workflow-coverage-map] ERR Makefile not found: {args.makefile}", file=sys.stderr)
        return 2
    report = build_report(args.makefile, args.tools_dir)
    output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_markdown(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
