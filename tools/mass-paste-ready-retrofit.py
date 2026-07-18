#!/usr/bin/env python3
"""Report missing paste-ready structure across submission drafts.

This is a non-mutating retrofit planner. It scans markdown drafts and reports
which gate-backed sections are missing so agents can batch-edit old artifacts
without weakening the gates or guessing from memory.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.mass_paste_ready_retrofit.v1"
L27_DIRECTIVES = {
    "selected_impact",
    "severity_tier",
    "listed_impact_proven",
    "evidence_class",
    "oos_traps",
    "stop_condition",
}
GATE_SCRIPTS = {
    "R24": "non-self-impact-check.py",
    "R27": "adjacent-finding-disclosure-check.py",
    "R23": "comparative-baseline-check.py",
    "R21": "permanent-impact-five-ask-template-check.py",
}
_GATE_MODULES: dict[str, Any] = {}

SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:\*\*)?\s*Severity(?:\s+rating)?(?:\*\*)?\s*[:\-]\s*(?:\*\*)?"
    r"(Critical|High|Medium|Low)\b"
)
FIELD_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?([A-Za-z][A-Za-z0-9 _-]{1,60})\s*:\s*(.+?)\s*$")
PLACEHOLDER_RE = re.compile(r"^(?:n/?a|none|todo|tbd|unknown|missing|\[\])\.?$", re.IGNORECASE)

MISSING_GUARD_RE = re.compile(
    r"\b(?:missing|omitted|lacks?|without)\s+(?:guard|validation|check|modifier|access\s+control|"
    r"reentrancy\s+guard|pause\s+check|bounds?\s+check)|"
    r"\b(?:asymmetric|unpaired|inconsistent)\s+(?:guard|validation|check|path)|"
    r"\b(?:guard|validation|check)\s+(?:asymmetry|gap)",
    re.IGNORECASE,
)
FUND_IMPACT_RE = re.compile(
    r"loss of funds|fund loss|direct loss|direct theft|theft of funds|"
    r"permanent freezing|freezing of funds|unauthorized withdraw|unauthorized transfer",
    re.IGNORECASE,
)
NON_SELF_RE = re.compile(
    r"non-self impact demonstrated|protocol-custody funds|funds the attacker does not control|"
    r"not in the attacker's wallet|victim .* balance|protocol .* balance",
    re.IGNORECASE,
)
ADJACENT_RE = re.compile(
    r"adjacent|sibling|related finding|same root cause|same bug class|"
    r"additional vulnerable|follow[- ]?up report|separate report",
    re.IGNORECASE,
)
COMPARATIVE_RE = re.compile(
    r"comparative|same[- ]workload|side[- ]by[- ]side|baseline|upstream|regression|"
    r"loosened|weakened|threshold|cap\s*=|vs\.?|versus|p95|p99|latency|throughput",
    re.IGNORECASE,
)
PERMANENT_RE = re.compile(
    r"permanent freezing|permanent[- ]class|permanently frozen|hardfork|required hardfork|"
    r"governance-required|requires governance|24h\+|chain halt|block production halt",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_gate(script_name: str) -> Any:
    cached = _GATE_MODULES.get(script_name)
    if cached is not None:
        return cached
    script_path = Path(__file__).resolve().with_name(script_name)
    module_name = "auditooor_gate_" + script_name.removesuffix(".py").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load gate script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    _GATE_MODULES[script_name] = module
    return module


def _run_gate(gate: str, path: Path) -> tuple[int, dict[str, Any]]:
    module = _load_gate(GATE_SCRIPTS[gate])
    if gate == "R23":
        return module.run(path, severity_override=None, strict=False)
    if gate in {"R24", "R27"}:
        return module.run(path, severity_override=None, poc_dir=[], strict=False)
    return module.run(path, strict=False)


def _gate_is_triggered(payload: dict[str, Any]) -> bool:
    verdict = payload.get("verdict")
    if verdict == "pass-out-of-scope":
        return False
    if verdict in {"error", None}:
        return False
    return True


def _field_key(raw: str) -> str:
    return raw.strip().lower().replace("-", "_").replace(" ", "_")


def _fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in FIELD_RE.finditer(text):
        key = _field_key(match.group(1))
        value = match.group(2).strip()
        if value and not PLACEHOLDER_RE.match(value):
            fields[key] = value
    return fields


def _severity(text: str, path: Path) -> str | None:
    match = SEVERITY_RE.search(text)
    if match:
        return match.group(1).capitalize()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity.capitalize()
    return None


def _high_plus(severity: str | None) -> bool:
    return severity in {"High", "Critical"}


def _has_heading(text: str, heading: str) -> bool:
    return bool(re.search(rf"(?im)^\s{{0,3}}#{{1,6}}\s+{heading}\b", text))


def discover(root: Path) -> list[Path]:
    if root.is_file():
        return [root.resolve()]
    return sorted(path.resolve() for path in root.rglob("*.md") if path.is_file())


def analyze(path: Path, *, gold_sections: set[str] | None = None) -> dict[str, Any]:
    text = _read(path)
    fields = _fields(text)
    severity = _severity(text, path)
    missing: list[str] = []
    triggers: list[str] = []
    gate_verdicts: dict[str, str] = {}

    missing_directives = sorted(L27_DIRECTIVES - set(fields))
    if missing_directives:
        missing.append("impact_contract_l27_directives")
    if not _has_heading(text, r"Impact Contract"):
        missing.append("impact_contract_section")

    if not re.search(r"(?im)^\s{0,3}#{2,6}\s+Program Impact Mapping\b", text):
        missing.append("program_impact_mapping")
    if not re.search(r"(?im)^\s{0,3}#{2,6}\s+Production Path\b", text) and _high_plus(severity):
        missing.append("production_path")
    if not re.search(r"(?im)^\s{0,3}#{3,6}\s+What the tests prove\b", text):
        missing.append("what_tests_prove")
    if not re.search(r"full[- ]suite regression|full suite .*pass|regression suite .*pass", text, re.IGNORECASE):
        missing.append("full_suite_regression_pass_line")

    missing_guard = bool(MISSING_GUARD_RE.search(text))
    if missing_guard:
        triggers.append("missing_guard")
        if not _has_heading(text, r"Enumerated Call Sites") and not re.search(r"<!--\s*l30-rebuttal:", text, re.IGNORECASE):
            missing.append("enumerated_call_sites")

    gate_map = {
        "R24": ("high_plus_fund_impact", "r24_non_self_impact_prose"),
        "R27": ("adjacent_disclosure", "r27_adjacent_finding_disclosure"),
        "R23": ("comparative_baseline", "r23_comparative_baseline"),
        "R21": ("permanent_impact", "r21_permanent_impact_five_ask"),
    }
    for gate, (trigger_name, missing_name) in gate_map.items():
        rc, payload = _run_gate(gate, path)
        verdict = str(payload.get("verdict") or f"rc-{rc}")
        gate_verdicts[gate] = verdict
        if _gate_is_triggered(payload):
            triggers.append(trigger_name)
        if rc == 1:
            missing.append(missing_name)

    gold_missing: list[str] = []
    if gold_sections:
        for section in sorted(gold_sections):
            if not _has_heading(text, re.escape(section)):
                gold_missing.append(section)

    return {
        "file": str(path),
        "severity": severity,
        "status": "needs_retrofit" if missing or gold_missing else "ok",
        "missing": sorted(set(missing)),
        "missing_l27_directives": missing_directives,
        "triggers": sorted(set(triggers)),
        "gate_verdicts": gate_verdicts,
        "gold_template_sections_missing": gold_missing,
    }


def extract_gold_sections(path: Path | None) -> set[str]:
    if path is None:
        return set()
    text = _read(path)
    sections = set()
    for match in re.finditer(r"(?im)^\s{0,3}#{2,3}\s+(.+?)\s*$", text):
        title = match.group(1).strip()
        if title in {
            "Impact Contract",
            "Program Impact Mapping",
            "Production Path",
            "Enumerated Call Sites",
            "Scope and Originality",
            "Recommended Fix",
        }:
            sections.add(title)
    return sections


def build_report(root: Path, *, gold_template: Path | None = None) -> dict[str, Any]:
    drafts = discover(root)
    gold_sections = extract_gold_sections(gold_template)
    rows = [analyze(path, gold_sections=gold_sections) for path in drafts]
    missing_counts: Counter[str] = Counter()
    trigger_counts: Counter[str] = Counter()
    for row in rows:
        missing_counts.update(row["missing"])
        trigger_counts.update(row["triggers"])
    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "root": str(root.resolve()),
        "gold_template": str(gold_template.resolve()) if gold_template else None,
        "draft_count": len(rows),
        "needs_retrofit_count": sum(1 for row in rows if row["status"] == "needs_retrofit"),
        "missing_counts": dict(sorted(missing_counts.items())),
        "trigger_counts": dict(sorted(trigger_counts.items())),
        "drafts": rows,
    }


def markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Mass Paste-Ready Retrofit Report",
        "",
        f"- Root: `{payload['root']}`",
        f"- Drafts scanned: {payload['draft_count']}",
        f"- Drafts needing retrofit: {payload['needs_retrofit_count']}",
        "",
        "## Missing Counts",
        "",
    ]
    for key, count in payload.get("missing_counts", {}).items():
        lines.append(f"- `{key}`: {count}")
    lines.extend(["", "## Drafts", ""])
    for row in payload.get("drafts", []):
        if row.get("status") == "ok":
            continue
        lines.append(f"### `{Path(row['file']).name}`")
        lines.append(f"- Severity: `{row.get('severity') or 'unknown'}`")
        if row.get("triggers"):
            lines.append("- Triggers: " + ", ".join(f"`{item}`" for item in row["triggers"]))
        if row.get("missing"):
            lines.append("- Missing: " + ", ".join(f"`{item}`" for item in row["missing"]))
        if row.get("missing_l27_directives"):
            lines.append("- Missing L27 directives: " + ", ".join(f"`{item}`" for item in row["missing_l27_directives"]))
        if row.get("gold_template_sections_missing"):
            lines.append("- Missing gold sections: " + ", ".join(f"`{item}`" for item in row["gold_template_sections_missing"]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Submission markdown file or directory to scan")
    parser.add_argument("--gold-template", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = parser.parse_args(argv)

    payload = build_report(args.root, gold_template=args.gold_template)
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(markdown_report(payload), encoding="utf-8")
    if args.json or not (args.out_json or args.out_md):
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["needs_retrofit_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
