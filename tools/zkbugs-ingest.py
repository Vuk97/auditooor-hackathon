#!/usr/bin/env python3
"""Ingest zkBugs into auditooor farming artifacts.

The public zkBugs site is backed by the zksecurity/zkbugs repository. This
tool intentionally works from a local checkout so farming stays repeatable,
offline-reviewable, and safe for PRs: clone/update the corpus outside this
tool, then point ``--zkbugs-root`` at it.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / ".audit_logs" / "zkbugs_farming"

SCHEMA = "auditooor.zkbugs_index.v2"

# Regexes for backfill of circuit-level metadata from code excerpts or
# vulnerability descriptions (Circom-focused; graceful empty on other DSLs).
TEMPLATE_RE = re.compile(r"template\s+(\w+)\s*(?:\([^)]*\))?\s*\{", re.MULTILINE)
SIGNAL_RE = re.compile(r"signal\s+(?:input|output)\s+(\w+)", re.MULTILINE)
COMPONENT_RE = re.compile(r"component\s+(\w+)\s*=", re.MULTILINE)


@dataclass(frozen=True)
class ZkBugRecord:
    title: str
    bug_id: str
    rel_path: str
    config_path: str
    dsl: str
    vulnerability: str
    impact: str
    root_cause: str
    project: str
    commit: str
    fix_commit: str
    reproduced: bool
    location_path: str
    location_function: str
    location_line: str
    source_links: list[str]
    source_ids: list[str]
    commands: dict[str, str]
    short_vulnerability: str
    short_exploit: str
    proposed_mitigation: str
    report_ids: list[str]
    report_files: list[str]
    report_text_files: list[str]
    priority_score: int
    priority_reasons: list[str]
    # v2 fields — empty defaults so v1 callers remain compatible
    template_name: str = ""
    signal_names: list[str] = field(default_factory=list)
    component_names: list[str] = field(default_factory=list)
    library_handle: str = ""


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _backfill_v2(item: dict[str, Any], dsl: str) -> tuple[str, list[str], list[str], str]:
    """Extract v2 circuit-level metadata from available text bodies.

    Returns (template_name, signal_names, component_names, library_handle).
    Runs regex extraction only on Circom DSL; other DSLs get empty defaults.
    """
    # --- library_handle: derive from project URL or location path ---
    project = _string(item.get("Project"))
    location = item.get("Location") if isinstance(item.get("Location"), dict) else {}
    loc_path = _string(location.get("Path")) if isinstance(location, dict) else ""
    library_handle = ""
    if project:
        # Extract repo name from GitHub URL: https://github.com/org/repo -> repo
        parts = project.rstrip("/").split("/")
        if len(parts) >= 2:
            library_handle = parts[-1]

    if dsl.lower() != "circom":
        # For non-Circom DSLs derive template_name from location function only
        loc_func = _string(location.get("Function")) if isinstance(location, dict) else ""
        return loc_func, [], [], library_handle

    # --- Collect text corpus to run regexes against ---
    text_parts: list[str] = []
    short_vuln = _string(item.get("Short Description of the Vulnerability"))
    short_exploit = _string(item.get("Short Description of the Exploit"))
    mitigation = _string(item.get("Proposed Mitigation"))
    # Location function is often the template name
    loc_func = _string(location.get("Function")) if isinstance(location, dict) else ""
    text_parts.extend([short_vuln, short_exploit, mitigation])
    body = "\n".join(text_parts)

    # --- template_name ---
    template_name = loc_func  # Best single-source: Location.Function
    if not template_name:
        m = TEMPLATE_RE.search(body)
        if m:
            template_name = m.group(1)

    # --- signal_names: scan body for backtick-wrapped signal names first ---
    # e.g. "`out[i]` is assigned..." → "out"
    backtick_signals = re.findall(r"`(\w+)(?:\[.*?\])?`", body)
    regex_signals = [m.group(1) for m in SIGNAL_RE.finditer(body)]
    signal_names = list(dict.fromkeys(backtick_signals[:8] + regex_signals[:8]))[:12]

    # --- component_names: from COMPONENT_RE on body ---
    component_names = list(dict.fromkeys(m.group(1) for m in COMPONENT_RE.finditer(body)))[:8]

    return template_name, signal_names, component_names, library_handle


def _bool(value: object) -> bool:
    return bool(value) if isinstance(value, bool) else False


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:120] or "zkbug"


def _source_links(source: object) -> tuple[list[str], list[str]]:
    links: list[str] = []
    ids: list[str] = []
    if not isinstance(source, dict):
        return links, ids
    for source_name, payload in source.items():
        if isinstance(payload, dict):
            link = _string(payload.get("Source Link"))
            bug_id = _string(payload.get("Bug ID"))
            if link:
                links.append(link)
            if bug_id:
                ids.append(f"{source_name}: {bug_id}")
        elif isinstance(payload, str):
            links.append(payload)
    return sorted(set(links)), sorted(set(ids))


def load_reports(root: Path) -> list[dict[str, Any]]:
    path = root / "reports" / "reports.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, list) else []


def _report_text_candidates(report_file: str) -> list[str]:
    path = Path(report_file)
    if path.suffix.lower() == ".pdf":
        return [str(path.with_suffix(".txt")), str(path.with_name(path.name + ".txt"))]
    if path.suffix.lower() in {".md", ".txt"}:
        return [str(path)]
    return []


def _report_matches(
    item: dict[str, Any],
    reports: list[dict[str, Any]],
    root: Path,
) -> tuple[list[str], list[str], list[str]]:
    project = _string(item.get("Project")).lower().rstrip("/")
    commit = _string(item.get("Commit")).lower().removeprefix("0x")[:10]
    source_links, source_ids = _source_links(item.get("Source"))
    hay = "\n".join(source_links + source_ids + [project]).lower()
    ids: list[str] = []
    files: list[str] = []
    text_files: list[str] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        rid = _string(report.get("ID"))
        rfile = _string(report.get("File"))
        rproject = _string(report.get("Project")).lower().rstrip("/")
        rcommit = _string(report.get("Commit")).lower().removeprefix("0x")
        matched = False
        if rid and rid.lower() in hay:
            matched = True
        if rfile and Path(rfile).stem.lower() in hay:
            matched = True
        if project and rproject and (project == rproject or project in rproject or rproject in project):
            matched = True
        if commit and rcommit and (commit.startswith(rcommit) or rcommit.startswith(commit)):
            matched = True
        if matched:
            if rid:
                ids.append(rid)
            if rfile:
                rel_file = str(Path("reports") / rfile)
                files.append(rel_file)
                for rel_text in _report_text_candidates(rel_file):
                    text_path = root / rel_text
                    if text_path.is_file() and text_path.stat().st_size > 0:
                        text_files.append(rel_text)
    return sorted(set(ids)), sorted(set(files)), sorted(set(text_files))


def _priority(
    item: dict[str, Any],
    links: list[str],
    report_files: list[str],
    report_text_files: list[str],
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if _bool(item.get("Reproduced")):
        score += 35
        reasons.append("reproduced")
    commands = item.get("Commands")
    if isinstance(commands, dict) and _string(commands.get("Reproduce")):
        score += 25
        reasons.append("has-reproduce-command")
    if _string(item.get("Short Description of the Exploit")):
        score += 15
        reasons.append("has-exploit-description")
    if _string(item.get("Fix Commit")):
        score += 10
        reasons.append("has-fix-commit")
    if links:
        score += 10
        reasons.append("has-source-link")
    if report_files:
        score += 10
        reasons.append("has-local-report")
    if report_text_files:
        score += 30
        reasons.append("has-local-report-text")
    impact = _string(item.get("Impact")).lower()
    if any(word in impact for word in ("soundness", "forg", "accepted")):
        score += 5
        reasons.append("soundness-impact")
    return score, reasons


def iter_config_paths(root: Path) -> Iterable[Path]:
    dataset = root / "dataset"
    if not dataset.is_dir():
        raise FileNotFoundError(f"missing zkBugs dataset directory: {dataset}")
    for path in sorted(dataset.rglob("zkbugs_config.json")):
        yield path


def load_records(root: Path) -> list[ZkBugRecord]:
    root = root.expanduser().resolve()
    reports = load_reports(root)
    records: list[ZkBugRecord] = []
    for config_path in iter_config_paths(root):
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {config_path}: {exc}") from exc
        if not isinstance(payload, dict):
            continue
        for title, item in payload.items():
            if not isinstance(item, dict):
                continue
            location = item.get("Location") if isinstance(item.get("Location"), dict) else {}
            commands = item.get("Commands") if isinstance(item.get("Commands"), dict) else {}
            links, source_ids = _source_links(item.get("Source"))
            report_ids, report_files, report_text_files = _report_matches(item, reports, root)
            score, reasons = _priority(item, links, report_files, report_text_files)
            dsl = _string(item.get("DSL"))
            template_name, signal_names, component_names, library_handle = _backfill_v2(item, dsl)
            records.append(
                ZkBugRecord(
                    title=str(title),
                    bug_id=_string(item.get("Id")),
                    rel_path=_string(item.get("Path")) or str(config_path.parent.relative_to(root)),
                    config_path=str(config_path.relative_to(root)),
                    dsl=dsl,
                    vulnerability=_string(item.get("Vulnerability")),
                    impact=_string(item.get("Impact")),
                    root_cause=_string(item.get("Root Cause")),
                    project=_string(item.get("Project")),
                    commit=_string(item.get("Commit")),
                    fix_commit=_string(item.get("Fix Commit")),
                    reproduced=_bool(item.get("Reproduced")),
                    location_path=_string(location.get("Path")) if isinstance(location, dict) else "",
                    location_function=_string(location.get("Function")) if isinstance(location, dict) else "",
                    location_line=_string(location.get("Line")) if isinstance(location, dict) else "",
                    source_links=links,
                    source_ids=source_ids,
                    commands={str(k): _string(v) for k, v in commands.items()} if isinstance(commands, dict) else {},
                    short_vulnerability=_string(item.get("Short Description of the Vulnerability")),
                    short_exploit=_string(item.get("Short Description of the Exploit")),
                    proposed_mitigation=_string(item.get("Proposed Mitigation")),
                    report_ids=report_ids,
                    report_files=report_files,
                    report_text_files=report_text_files,
                    priority_score=score,
                    priority_reasons=reasons,
                    template_name=template_name,
                    signal_names=signal_names,
                    component_names=component_names,
                    library_handle=library_handle,
                )
            )
    records.sort(key=lambda rec: (-rec.priority_score, rec.dsl.lower(), rec.title.lower()))
    return records


def summarize(records: list[ZkBugRecord]) -> dict[str, Any]:
    by_dsl: dict[str, int] = {}
    by_vulnerability: dict[str, int] = {}
    reproduced = 0
    with_reproduce_command = 0
    with_local_report = 0
    with_local_report_text = 0
    for rec in records:
        by_dsl[rec.dsl or "unknown"] = by_dsl.get(rec.dsl or "unknown", 0) + 1
        by_vulnerability[rec.vulnerability or "unknown"] = by_vulnerability.get(rec.vulnerability or "unknown", 0) + 1
        if rec.reproduced:
            reproduced += 1
        if rec.commands.get("Reproduce"):
            with_reproduce_command += 1
        if rec.report_files:
            with_local_report += 1
        if rec.report_text_files:
            with_local_report_text += 1
    return {
        "total": len(records),
        "reproduced": reproduced,
        "with_reproduce_command": with_reproduce_command,
        "with_local_report": with_local_report,
        "with_local_report_text": with_local_report_text,
        "by_dsl": dict(sorted(by_dsl.items())),
        "by_vulnerability": dict(sorted(by_vulnerability.items(), key=lambda item: (-item[1], item[0]))),
    }


def render_index(records: list[ZkBugRecord], *, limit: int = 0) -> str:
    summary = summarize(records)
    shown = records[:limit] if limit > 0 else records
    lines = [
        "# zkBugs Farming Index",
        "",
        "Generated from a local `zksecurity/zkbugs` checkout. This index is mining",
        "input only: every promoted pattern still needs production-path truth,",
        "vulnerable/clean smoke fixtures, and Codex final review.",
        "",
        "## Summary",
        "",
        f"- Total bugs: `{summary['total']}`",
        f"- Reproduced in corpus: `{summary['reproduced']}`",
        f"- With reproduce command: `{summary['with_reproduce_command']}`",
        f"- With matched local report/PDF: `{summary['with_local_report']}`",
        f"- With extracted local report text: `{summary['with_local_report_text']}`",
        "",
        "## DSL Counts",
        "",
    ]
    for dsl, count in summary["by_dsl"].items():
        lines.append(f"- `{dsl}`: `{count}`")
    lines.extend([
        "",
        "## Top Farming Rows",
        "",
        "| Score | DSL | Vulnerability | Impact | Title | Source |",
        "|---:|---|---|---|---|---|",
    ])
    for rec in shown:
        source = rec.source_links[0] if rec.source_links else rec.project
        lines.append(
            f"| {rec.priority_score} | `{rec.dsl}` | `{rec.vulnerability}` | `{rec.impact}` | "
            f"{rec.title} | {source} |"
        )
    lines.extend([
        "",
        "## Guardrails",
        "",
        "- Kimi should extract source/root-cause details from one DSL/project packet at a time.",
        "- Minimax should kill candidates for false positives, duplicate corpus rows, and missing exploitability.",
        "- Claude should only draft detector/fixture/replay PRs after a row has concrete code and source links.",
        "- Codex is final verifier: no pattern promotion without smoke-fire or a replayable counterexample.",
    ])
    return "\n".join(lines) + "\n"


def render_brief(rec: ZkBugRecord) -> str:
    source_lines = "\n".join(f"- {link}" for link in rec.source_links) or "- No source link in config"
    report_lines = "\n".join(f"- `{path}`" for path in rec.report_files) or "- No matched local report/PDF"
    report_text_lines = "\n".join(f"- `{path}`" for path in rec.report_text_files) or (
        "- No matched extracted report text. If this row cites local PDFs, run "
        "`make extract DIR=<zkbugs-root>/reports/documents` and re-run `make zkbugs-ingest`."
    )
    commands = "\n".join(f"- `{name}`: `{cmd}`" for name, cmd in rec.commands.items() if cmd) or "- No runnable commands in config"
    return f"""# zkBugs Farming Brief: {rec.title}

## Corpus Facts

- ID: `{rec.bug_id}`
- Dataset path: `{rec.rel_path}`
- Config path: `{rec.config_path}`
- DSL: `{rec.dsl}`
- Vulnerability: `{rec.vulnerability}`
- Impact: `{rec.impact}`
- Root cause: `{rec.root_cause}`
- Reproduced by zkBugs: `{rec.reproduced}`
- Priority score: `{rec.priority_score}` ({", ".join(rec.priority_reasons) or "no boost"})

## Code Location

- Project: `{rec.project}`
- Commit: `{rec.commit}`
- Fix commit: `{rec.fix_commit}`
- Path: `{rec.location_path}`
- Function: `{rec.location_function}`
- Line: `{rec.location_line}`

## Sources

{source_lines}

## Local Reports / PDFs

{report_lines}

## Local Report Text

{report_text_lines}

## Corpus Commands

{commands}

## Vulnerability Summary

{rec.short_vulnerability or "No short vulnerability description in config."}

## Exploit Summary

{rec.short_exploit or "No short exploit description in config."}

## Proposed Mitigation

{rec.proposed_mitigation or "No mitigation description in config."}

## Farming Instructions

1. Kimi: read only this bug directory, linked source, and nearby fixed commit. Extract the minimal root-cause predicate and the exact code shape that would generalize.
2. Minimax: adversarially reject if the predicate is too broad, duplicate, not checkable, or only proves a toy circuit with no reusable audit signal.
3. Claude: if Kimi+Minimax survive, draft one auditooor detector/fixture/replay task. Do not write submission text.
4. Codex: promote only if there is a vulnerable/clean fixture, replayable counterexample, or explicit reason this remains advisory-only.
"""


def write_briefs(records: list[ZkBugRecord], briefs_dir: Path, *, limit: int) -> list[str]:
    briefs_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    selected = records if limit <= 0 else records[:limit]
    for rec in selected:
        name = f"{_slug(rec.dsl)}__{_slug(rec.vulnerability)}__{_slug(rec.title)}.md"
        path = briefs_dir / name
        path.write_text(render_brief(rec), encoding="utf-8")
        written.append(str(path))
    return written


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zkbugs-root", type=Path, required=True, help="Local checkout of https://github.com/zksecurity/zkbugs")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--brief-limit", type=int, default=20, help="Number of top farming briefs to write; 0 means all")
    parser.add_argument("--index-limit", type=int, default=50, help="Number of top rows to show in Markdown index; 0 means all")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    records = load_records(args.zkbugs_root)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    briefs_dir = args.out_dir / "briefs"
    written_briefs = write_briefs(records, briefs_dir, limit=max(0, args.brief_limit))
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "https://github.com/zksecurity/zkbugs",
        "zkbugs_root": str(args.zkbugs_root.expanduser().resolve()),
        "summary": summarize(records),
        "records": [asdict(rec) for rec in records],
        "briefs": written_briefs,
    }
    (args.out_dir / "zkbugs_index.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.out_dir / "zkbugs_index.md").write_text(render_index(records, limit=args.index_limit), encoding="utf-8")
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "brief_count": len(written_briefs)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
