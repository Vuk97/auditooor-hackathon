#!/usr/bin/env python3
"""Build a pre-engagement prior-disclosure index.

HACKERMAN V3 Lane A1 moves duplicate intelligence to engagement start. This
tool is deliberately local-first: it does not scrape bounty platforms in the
first slice. It indexes settled outcome rows, known dupe-cause notes, and the
workspace's prior-audit/submission artifacts into one searchable JSON file:

    <workspace>/.auditooor/prior_disclosure_index.json

The artifact is an attention and judgment input for prefiling stress tests,
L31 dupe preflight, and source-read planning. It is not proof by itself.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.prior_disclosure_index.v1"

ATTACK_CLASS_PATTERNS: tuple[tuple[str, str], ...] = (
    ("duplicate-prior-disclosure", r"\b(duplicate|dupe|same root|same class|prior finding)\b"),
    ("access-control", r"\b(access control|onlyowner|only owner|role|permission|privileged|admin|owner)\b"),
    ("oracle-price", r"\b(oracle|price|nav|valuation|stale price|feed)\b"),
    ("share-inflation", r"\b(share|first deposit|inflation|donation|erc4626|rounding)\b"),
    ("rounding-accounting", r"\b(rounding|truncat|precision|accounting|drift|dust|overflow|underflow)\b"),
    ("fund-freeze", r"\b(freeze|frozen|halt|bricking|permanent(?:ly)? reverts|liveness)\b"),
    ("fund-theft", r"\b(theft|steal|drain|loss of funds|sweep|refund flush)\b"),
    ("reentrancy", r"\b(reentrancy|callback|onerc|hook)\b"),
    ("bridge-domain", r"\b(bridge|replay|domain|chain id|source chain|destination)\b"),
    ("signature-replay", r"\b(signature|permit|eip-712|replay|nonce)\b"),
    ("governance", r"\b(governance|vote|voting|proposal|guardian|veto)\b"),
    ("generic-dos", r"\b(generic dos|rpc pressure|checktx pressure|rate limit|dos)\b"),
)

HIGH_RISK_OUTCOMES = {"dupe", "duplicate", "rejected", "declined", "out_of_scope", "oos", "spam"}
CODE_TOKEN_RE = re.compile(r"`([^`]{2,120})`|\b([A-Z][A-Za-z0-9_]{2,80})\b|\b([a-zA-Z_][A-Za-z0-9_]{2,80}\(\))")
WORD_RE = re.compile(r"[a-z0-9][a-z0-9_\-]{2,}")
IDENTIFIER_RE = re.compile(r"\b(?:lead\s+)?[a-z0-9]+(?:[-_.][a-z0-9]+)+\b|#[a-z0-9_.-]+", re.IGNORECASE)
STOPWORDS = {
    "about",
    "after",
    "against",
    "cause",
    "causes",
    "current",
    "finding",
    "findings",
    "lead",
    "report",
    "root",
    "same",
    "state",
    "status",
    "submission",
    "submissions",
    "that",
    "then",
    "this",
    "with",
}


@dataclass
class Row:
    row_id: str
    source_type: str
    source_ref: str
    title: str
    workspace: str = ""
    finding_id: str = ""
    status: str = ""
    outcome_class: str = ""
    severity: str = ""
    attack_classes: list[str] = field(default_factory=list)
    component_hints: list[str] = field(default_factory=list)
    function_hints: list[str] = field(default_factory=list)
    dupe_risk_weight: int = 0
    text_excerpt: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "workspace": self.workspace,
            "finding_id": self.finding_id,
            "title": self.title,
            "status": self.status,
            "outcome_class": self.outcome_class,
            "severity": self.severity,
            "attack_classes": self.attack_classes,
            "component_hints": self.component_hints,
            "function_hints": self.function_hints,
            "dupe_risk_weight": self.dupe_risk_weight,
            "text_excerpt": self.text_excerpt,
            "search_text": search_text(
                self.workspace,
                self.finding_id,
                self.title,
                self.status,
                self.outcome_class,
                " ".join(self.attack_classes),
                " ".join(self.component_hints),
                self.text_excerpt,
            ),
        }


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_id(*parts: str) -> str:
    raw = "|".join(p for p in parts if p)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def read_text(path: Path, limit: int | None = None) -> str:
    data = path.read_text(encoding="utf-8", errors="replace")
    return data if limit is None else data[:limit]


def compact(s: str, limit: int = 500) -> str:
    return " ".join(str(s or "").split())[:limit]


def search_text(*parts: str) -> str:
    return " ".join(compact(p, 2000).lower() for p in parts if p)


def token_set(text: str) -> set[str]:
    return {
        m.group(0).strip("-_").lower()
        for m in WORD_RE.finditer(text.lower())
        if m.group(0).strip("-_").lower() not in STOPWORDS
    }


def identifier_terms(text: str) -> set[str]:
    out: set[str] = set()
    for match in IDENTIFIER_RE.finditer(text.lower()):
        value = re.sub(r"\s+", "-", match.group(0).strip().lstrip("#"))
        value = value.strip("-_.")
        if not value:
            continue
        out.add(value)
        if value.startswith("lead-"):
            out.add(value.removeprefix("lead-"))
    return out


def infer_attack_classes(text: str) -> list[str]:
    hits: list[str] = []
    for name, pat in ATTACK_CLASS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(name)
    return hits or ["unknown"]


def extract_code_hints(text: str) -> tuple[list[str], list[str]]:
    components: list[str] = []
    functions: list[str] = []
    for match in CODE_TOKEN_RE.finditer(text):
        value = next((g for g in match.groups() if g), "")
        if not value:
            continue
        value = value.strip()
        if value.endswith("()"):
            functions.append(value[:-2])
        elif "." in value and value.split(".")[-1].endswith("()"):
            functions.append(value.split(".")[-1][:-2])
        elif re.search(r"[A-Z]", value):
            components.append(value)
    return sorted(set(components))[:12], sorted(set(functions))[:12]


def normalize_outcome(value: str) -> str:
    low = str(value or "").lower()
    if "duplicate" in low or "dupe" in low:
        return "duplicate"
    if "out of scope" in low or "oos" in low:
        return "out_of_scope"
    if "spam" in low:
        return "spam"
    if "reject" in low or "declined" in low:
        return "rejected"
    if "paid" in low or "accepted" in low or "confirmed" in low:
        return "accepted"
    if "review" in low:
        return "in_review"
    if "pending" in low:
        return "pending"
    return low.replace(" ", "_")[:40]


def risk_weight(outcome: str, status: str, source_type: str) -> int:
    joined = f"{outcome} {status}".lower()
    if any(tok in joined for tok in ("duplicate", "dupe")):
        return 100
    if any(tok in joined for tok in ("out of scope", "oos", "spam")):
        return 90
    if any(tok in joined for tok in ("rejected", "declined")):
        return 75
    if source_type == "dupe_causes":
        return 100
    if source_type.startswith("prior_audit"):
        return 55
    return 25


def row_from_parts(
    *,
    source_type: str,
    source_ref: str,
    title: str,
    workspace: str = "",
    finding_id: str = "",
    status: str = "",
    outcome_class: str = "",
    severity: str = "",
    text_excerpt: str = "",
) -> Row:
    basis = search_text(title, status, outcome_class, severity, text_excerpt)
    components, functions = extract_code_hints(basis)
    normalized = normalize_outcome(outcome_class or status)
    return Row(
        row_id=f"{source_type}:{stable_id(source_ref, title, finding_id)}",
        source_type=source_type,
        source_ref=source_ref,
        title=compact(title, 240) or compact(text_excerpt, 120) or source_ref,
        workspace=workspace,
        finding_id=finding_id,
        status=compact(status, 180),
        outcome_class=normalized,
        severity=compact(severity, 40),
        attack_classes=infer_attack_classes(basis),
        component_hints=components,
        function_hints=functions,
        dupe_risk_weight=risk_weight(normalized, status, source_type),
        text_excerpt=compact(text_excerpt, 600),
    )


def iter_outcome_rows(path: Path) -> Iterable[Row]:
    if not path.is_file():
        return
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        title = str(data.get("title") or data.get("submission_id") or data.get("finding_id") or "")
        status = str(data.get("status") or data.get("outcome") or data.get("outcome_class") or "")
        yield row_from_parts(
            source_type="outcomes_jsonl",
            source_ref=f"{path}:{line_no}",
            title=title,
            workspace=str(data.get("workspace") or data.get("engagement") or ""),
            finding_id=str(data.get("finding_id") or data.get("submission_id") or ""),
            status=status,
            outcome_class=str(data.get("outcome_class") or data.get("outcome") or status),
            severity=str(data.get("severity") or data.get("severity_claimed") or data.get("severity_awarded") or ""),
            text_excerpt=json.dumps(data, sort_keys=True)[:900],
        )


def iter_dupe_causes(path: Path) -> Iterable[Row]:
    if not path.is_file():
        return
    text = read_text(path)
    chunks = re.split(r"(?m)^###\s+", text)
    for idx, chunk in enumerate(chunks[1:], start=1):
        lines = chunk.splitlines()
        if not lines:
            continue
        heading = lines[0].strip()
        body = "\n".join(lines[1:]).strip()
        m = re.match(r"([^/\s]+)/([^—]+)", heading)
        workspace = m.group(1).strip() if m else ""
        finding_id = m.group(2).strip() if m else heading.split("—", 1)[0].strip()
        yield row_from_parts(
            source_type="dupe_causes",
            source_ref=f"{path}:section-{idx}",
            title=heading,
            workspace=workspace,
            finding_id=finding_id,
            status="DUPE",
            outcome_class="duplicate",
            severity="",
            text_excerpt=body[:900],
        )


def iter_tsv_findings(path: Path, workspace: str) -> Iterable[Row]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for idx, data in enumerate(reader, start=2):
            title = data.get("title") or data.get("finding") or data.get("name") or ""
            if not title:
                continue
            yield row_from_parts(
                source_type="prior_audit_tsv",
                source_ref=f"{path}:{idx}",
                title=title,
                workspace=workspace,
                finding_id=data.get("id") or data.get("finding_id") or "",
                status=data.get("status") or "prior-audit",
                outcome_class="prior_audit",
                severity=data.get("severity") or data.get("risk") or "",
                text_excerpt=json.dumps(data, sort_keys=True)[:900],
            )


def iter_markdown_headings(path: Path, workspace: str, source_type: str) -> Iterable[Row]:
    if not path.is_file():
        return
    text = read_text(path, limit=500_000)
    lines = text.splitlines()
    emitted = 0
    for idx, line in enumerate(lines, start=1):
        m = re.match(r"^\s{0,3}#{1,4}\s+(.{6,240})$", line)
        if not m:
            continue
        title = m.group(1).strip()
        if title.lower() in {"schema", "entries", "meta-rules derived from entries", "summary"}:
            continue
        excerpt = "\n".join(lines[idx : idx + 8])
        emitted += 1
        yield row_from_parts(
            source_type=source_type,
            source_ref=f"{path}:{idx}",
            title=title,
            workspace=workspace,
            finding_id="",
            status="prior-artifact",
            outcome_class="prior_audit" if "prior" in source_type else "workspace_submission",
            severity="",
            text_excerpt=excerpt,
        )
        if emitted >= 200:
            break


def iter_workspace_rows(workspace: Path) -> Iterable[Row]:
    ws_name = workspace.name
    for tsv in sorted(workspace.glob("prior_audits/.ingested_findings.tsv")):
        yield from iter_tsv_findings(tsv, ws_name)
    for md in sorted(workspace.glob("prior_audits/DIGEST_*.md")):
        yield from iter_markdown_headings(md, ws_name, "prior_audit_digest")
    for md in sorted(workspace.glob("PRIOR_CONCERNS.md")):
        yield from iter_markdown_headings(md, ws_name, "prior_concerns")
    for md in sorted(workspace.glob("submissions/SUBMISSIONS.md")) + sorted(workspace.glob("SUBMISSIONS.md")):
        yield from iter_markdown_headings(md, ws_name, "workspace_submissions")


def iter_cross_workspace_submission_rows(audits_root: Path, current_workspace: Path) -> Iterable[Row]:
    if not audits_root.is_dir():
        return
    seen: set[Path] = set()
    for path in sorted(audits_root.glob("*/submissions/SUBMISSIONS.md")) + sorted(audits_root.glob("*/SUBMISSIONS.md")):
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            workspace = path.parent.parent if path.parent.name == "submissions" else path.parent
            source_type = "workspace_submissions" if workspace.resolve() == current_workspace.resolve() else "cross_workspace_submissions"
            yield from iter_markdown_headings(path, workspace.name, source_type)
        except OSError:
            continue


def dedupe_rows(rows: Iterable[Row]) -> list[Row]:
    best: dict[str, Row] = {}
    for row in rows:
        key = search_text(row.workspace, row.finding_id, row.title)[:320]
        old = best.get(key)
        if old is None or row.dupe_risk_weight > old.dupe_risk_weight:
            best[key] = row
    return sorted(best.values(), key=lambda r: (-r.dupe_risk_weight, r.workspace, r.title.lower()))


def build_indexes(rows: list[Row]) -> dict[str, Any]:
    attack_index: dict[str, list[str]] = defaultdict(list)
    component_index: dict[str, list[str]] = defaultdict(list)
    workspace_index: dict[str, list[str]] = defaultdict(list)
    outcome_index: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        for klass in row.attack_classes:
            attack_index[klass].append(row.row_id)
        for component in row.component_hints:
            component_index[component.lower()].append(row.row_id)
        workspace_index[row.workspace or "unknown"].append(row.row_id)
        outcome_index[row.outcome_class or "unknown"].append(row.row_id)
    return {
        "by_attack_class": dict(sorted(attack_index.items())),
        "by_component": dict(sorted(component_index.items())),
        "by_workspace": dict(sorted(workspace_index.items())),
        "by_outcome": dict(sorted(outcome_index.items())),
    }


def score_match(row: dict[str, Any], query: str) -> int:
    q = token_set(query)
    q_ids = identifier_terms(query)
    if not q and not q_ids:
        return 0
    text = search_text(
        str(row.get("workspace", "")),
        str(row.get("finding_id", "")),
        str(row.get("title", "")),
        str(row.get("search_text", "")),
        str(row.get("text_excerpt", "")),
    )
    r = token_set(text)
    r_ids = identifier_terms(text)
    overlap = len(q & r)
    phrase_bonus = 12 if query.lower() in text else 0
    component_bonus = 8 if any(str(c).lower() in query.lower() for c in row.get("component_hints", [])) else 0
    identifier_bonus = 30 * len(q_ids & r_ids)
    workspace_bonus = 10 if str(row.get("workspace", "")).lower() in q else 0
    evidence_score = overlap * 3 + phrase_bonus + component_bonus + identifier_bonus + workspace_bonus
    if evidence_score == 0:
        return 0
    risk_bonus = min(int(row.get("dupe_risk_weight") or 0) // 20, 5)
    return evidence_score + risk_bonus


def query_index(payload: dict[str, Any], query: str, *, limit: int = 8) -> list[dict[str, Any]]:
    scored: list[tuple[int, dict[str, Any]]] = []
    for row in payload.get("rows", []):
        score = score_match(row, query)
        if score > 0:
            scored.append((score, row))
    scored.sort(key=lambda x: (-x[0], -int(x[1].get("dupe_risk_weight") or 0), x[1].get("title", "")))
    out: list[dict[str, Any]] = []
    for score, row in scored[:limit]:
        item = dict(row)
        item["match_score"] = score
        out.append(item)
    return out


def build_payload(
    *,
    workspace: Path,
    repo_root: Path,
    outcomes_path: Path,
    dupe_causes_path: Path,
    audits_root: Path | None = None,
    target: str = "",
) -> dict[str, Any]:
    rows = dedupe_rows([
        *iter_outcome_rows(outcomes_path),
        *iter_dupe_causes(dupe_causes_path),
        *iter_workspace_rows(workspace),
        *(iter_cross_workspace_submission_rows(audits_root, workspace) if audits_root else []),
    ])
    row_dicts = [r.as_dict() for r in rows]
    summary = Counter(r.outcome_class or "unknown" for r in rows)
    source_counts = Counter(r.source_type for r in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "workspace_path": str(workspace),
        "workspace": workspace.name,
        "target": target or workspace.name,
        "repo_root": str(repo_root),
        "source_refs": {
            "outcomes_jsonl": str(outcomes_path),
            "dupe_causes": str(dupe_causes_path),
            "audits_root": str(audits_root) if audits_root else "",
            "workspace_prior_audits": str(workspace / "prior_audits"),
            "workspace_submissions": str(workspace / "submissions"),
        },
        "summary": {
            "total_rows": len(row_dicts),
            "by_outcome": dict(sorted(summary.items())),
            "by_source_type": dict(sorted(source_counts.items())),
            "high_dupe_risk_rows": sum(1 for r in rows if r.dupe_risk_weight >= 75),
        },
        "rows": row_dicts,
        "class_index": build_indexes(rows),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", required=True, help="Audit workspace root")
    p.add_argument("--target", default="", help="Target/project label")
    p.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    p.add_argument("--audits-root", default="", help="Root containing sibling audit workspaces (default: workspace parent)")
    p.add_argument("--outcomes", default="", help="Override reference/outcomes.jsonl")
    p.add_argument("--dupe-causes", default="", help="Override reference/DUPE_CAUSES.md")
    p.add_argument("--out", default="", help="Output path (default <ws>/.auditooor/prior_disclosure_index.json)")
    p.add_argument("--query", action="append", default=[], help="Probe query to score against the built index")
    p.add_argument("--json", action="store_true", help="Print payload JSON")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[prior-disclosure-index] workspace not found: {workspace}", file=sys.stderr)
        return 2
    repo_root = Path(args.repo_root).expanduser().resolve()
    outcomes = Path(args.outcomes).expanduser().resolve() if args.outcomes else repo_root / "reference" / "outcomes.jsonl"
    dupe_causes = Path(args.dupe_causes).expanduser().resolve() if args.dupe_causes else repo_root / "reference" / "DUPE_CAUSES.md"
    audits_root = Path(args.audits_root).expanduser().resolve() if args.audits_root else workspace.parent
    payload = build_payload(
        workspace=workspace,
        repo_root=repo_root,
        outcomes_path=outcomes,
        dupe_causes_path=dupe_causes,
        audits_root=audits_root,
        target=args.target,
    )
    if args.query:
        payload["query_results"] = {q: query_index(payload, q) for q in args.query}

    out = Path(args.out).expanduser().resolve() if args.out else workspace / ".auditooor" / "prior_disclosure_index.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[prior-disclosure-index] wrote {out}")
        print(
            f"[prior-disclosure-index] rows={payload['summary']['total_rows']} "
            f"high_dupe_risk={payload['summary']['high_dupe_risk_rows']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
