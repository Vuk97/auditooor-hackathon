#!/usr/bin/env python3
"""Brief-time OOS / AI-FP / known-issue preflight for dispatch briefs.

CAP-GAP-93: promotion-time gates are too late for drill workers. This helper
scans workspace bounty catalogs and nearby negative tests before a candidate is
drilled, then renders the context into the worker brief.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.dispatch_oos_preflight.v1"
REDUCED_SEVERITY = "CANDIDATE-FOR-EXTENSION-DISTINCT-ARGUMENT"

CAT_OOS = "oos"
CAT_AI_FP = "ai_fp"
CAT_KNOWN = "known_issue"
CAT_TRUST = "trust_assumption"
CAT_SEVERITY_OOS = "severity_oos"
CAT_SCOPE_OOS = "scope_oos"
CAT_PRIOR_ACK = "prior_acknowledgement"
CAT_DESIGN = "design_intent"

IMPORTANT_SHORT_TOKENS = {
    "ai",
    "fp",
    "fot",
    "mev",
    "oos",
    "dos",
    "fee",
    "eip",
}

STOPWORDS = {
    "about",
    "after",
    "against",
    "also",
    "already",
    "and",
    "any",
    "are",
    "asset",
    "audit",
    "before",
    "brief",
    "bug",
    "can",
    "candidate",
    "check",
    "claim",
    "class",
    "code",
    "contract",
    "contracts",
    "does",
    "drill",
    "file",
    "files",
    "finding",
    "for",
    "from",
    "has",
    "have",
    "impact",
    "into",
    "issue",
    "line",
    "match",
    "may",
    "not",
    "path",
    "program",
    "row",
    "rows",
    "scope",
    "severity",
    "source",
    "state",
    "target",
    "that",
    "the",
    "this",
    "under",
    "uses",
    "using",
    "with",
    "without",
}

STRONG_MATCH_TOKENS = {
    "acknowledged",
    "bounty",
    "bydesign",
    "cooldown",
    "depeg",
    "eip1153",
    "falsepositive",
    "feeontransfer",
    "frontrun",
    "frontrunning",
    "issuer",
    "knownissue",
    "mempool",
    "mev",
    "minout",
    "oracle",
    "sandwich",
    "slippage",
    "stablecoin",
    "testnet",
    "transient",
    "trusted",
}

OOS_LINE_RE = re.compile(
    r"\b(out[\s-]of[\s-]scope|OOS|not\s+in\s+scope|not\s+eligible|excluded)\b",
    re.IGNORECASE,
)
AI_FP_RE = re.compile(r"\b(AI[\s-]*(?:FP|false[\s-]positive)|false[\s-]positive)\b", re.IGNORECASE)
KNOWN_RE = re.compile(
    r"\b(known\s+issue|acknowledged|accepted\s+risk|risk[\s-]accepted|won'?t[\s-]?fix|wont[\s-]?fix|SRL|SE-P\d+|SUA-\w+|SSA-\w+|SA2-\w+)\b",
    re.IGNORECASE,
)
DESIGN_RE = re.compile(
    r"\b(by[\s-]design|designed[\s-]as[\s-]intended|intended\s+behavior|design\s+(?:choice|decision)|documented\s+behavior)\b",
    re.IGNORECASE,
)
TRUST_RE = re.compile(r"\b(trust\s+assumption|trusted|issuer|sidecar|sequencer|operator)\b", re.IGNORECASE)
NEGATIVE_TEST_RE = re.compile(
    r"(must[_\s-]?be[_\s-]?fresh|mustbefresh|cannot|cant|revert|reverts|notallowed|not_allowed|negative|oos|disprov|notvalid|not_valid|fails|reject)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Clause:
    clause_id: str
    category: str
    source: str
    line: int
    text: str
    section: str


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except (OSError, ValueError):
        return str(path)


def _tokenize(text: str) -> set[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or "")
    raw = re.split(r"[^A-Za-z0-9]+", text.lower())
    out: set[str] = set()
    for tok in raw:
        if not tok:
            continue
        compact = tok.replace("-", "")
        if len(tok) < 4 and tok not in IMPORTANT_SHORT_TOKENS:
            continue
        if tok in STOPWORDS:
            continue
        out.add(tok)
        if compact != tok and compact:
            out.add(compact)
    # Add compact phrase helpers for common catalog classes.
    low = (text or "").lower()
    phrase_map = {
        "fee-on-transfer": "feeontransfer",
        "fee on transfer": "feeontransfer",
        "front-running": "frontrunning",
        "front running": "frontrunning",
        "false-positive": "falsepositive",
        "false positive": "falsepositive",
        "known issue": "knownissue",
        "by design": "bydesign",
        "eip-1153": "eip1153",
    }
    for phrase, token in phrase_map.items():
        if phrase in low:
            out.add(token)
    return out


def _candidate_text(candidate: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "id",
        "candidate_id",
        "angle_id",
        "title",
        "name",
        "cluster",
        "attack_class",
        "invariant_id",
        "detector",
        "reason",
        "snippet",
        "hypothesis",
        "candidate_text",
        "file",
        "path",
        "function",
    ):
        val = candidate.get(key)
        if isinstance(val, str):
            parts.append(val)
    for key in ("contracts", "files", "tags"):
        val = candidate.get(key)
        if isinstance(val, list):
            parts.extend(str(item) for item in val)
    return "\n".join(parts)


def _section_category(path: Path, section: str, line: str) -> str:
    joined = f"{section}\n{line}"
    low = joined.lower()
    name = path.name.lower()
    if AI_FP_RE.search(joined) or "ai-tool false" in low:
        return CAT_AI_FP
    if "trust assumption" in low or (name == "bug_bounty.md" and TRUST_RE.search(joined) and "trust" in low):
        return CAT_TRUST
    if KNOWN_RE.search(joined) or "acknowledged design" in low:
        return CAT_KNOWN
    if DESIGN_RE.search(joined):
        return CAT_DESIGN
    if name.startswith("severity") and OOS_LINE_RE.search(joined):
        return CAT_SEVERITY_OOS
    if name.startswith("scope") and OOS_LINE_RE.search(joined):
        return CAT_SCOPE_OOS
    if OOS_LINE_RE.search(joined) or "out of scope" in low or "out-of-scope" in low:
        return CAT_OOS
    if "prior_audits" in str(path) and (KNOWN_RE.search(joined) or DESIGN_RE.search(joined)):
        return CAT_PRIOR_ACK
    return ""


def _extract_clause_id(line: str, fallback: str) -> str:
    patterns = (
        r"\b(?:OOS|AI-FP|SE-P|SUA|SSA|SA2|SRL)[-_ ]?\d+(?:\.\d+)?\b",
        r"\brow\s+\d+\b",
        r"^\s*\|?\s*(\d{1,3})\s*\|",
    )
    for pat in patterns:
        m = re.search(pat, line, re.IGNORECASE)
        if not m:
            continue
        if m.groups():
            return f"row-{m.group(1)}"
        return re.sub(r"\s+", "-", m.group(0).strip())
    return fallback


def _candidate_catalog_paths(ws: Path) -> list[Path]:
    out: list[Path] = []
    names = ("BUG_BOUNTY.md", "KNOWN_ISSUES.md", "OOS.md", "SEVERITY.md", "SCOPE.md")
    for name in names:
        p = ws / name
        if p.is_file():
            out.append(p)
    src = ws / "src"
    if src.is_dir():
        for name in ("BUG_BOUNTY.md", "KNOWN_ISSUES.md", "OOS.md"):
            out.extend(sorted(src.rglob(name))[:20])
    prior = ws / "prior_audits"
    if prior.is_dir():
        out.extend(sorted(prior.glob("DIGEST_*.md"))[:20])
        out.extend(sorted(prior.glob("*.txt"))[:20])
        out.extend(sorted(prior.glob("*.md"))[:20])
    # Preserve order while removing duplicates.
    seen: set[Path] = set()
    deduped: list[Path] = []
    for p in out:
        try:
            rp = p.resolve()
        except OSError:
            rp = p
        if rp in seen:
            continue
        seen.add(rp)
        deduped.append(p)
    return deduped


def _category_from_index_row(row: dict[str, Any]) -> str:
    raw = " ".join(
        str(row.get(key) or "")
        for key in ("category", "class", "semantic_class", "source_section", "kind", "clause")
    )
    low = raw.lower()
    if "ai" in low and ("fp" in low or "false" in low):
        return CAT_AI_FP
    if "trust" in low:
        return CAT_TRUST
    if "known" in low or "ack" in low or "risk" in low:
        return CAT_KNOWN
    if "design" in low:
        return CAT_DESIGN
    if "scope" in low and "oos" in low:
        return CAT_SCOPE_OOS
    if "severity" in low and "oos" in low:
        return CAT_SEVERITY_OOS
    if "oos" in low or "out" in low:
        return CAT_OOS
    phrase = str(row.get("phrase") or row.get("text") or row.get("description") or "")
    return _section_category(Path("BUG_BOUNTY.md"), raw, phrase) or CAT_OOS


def _clauses_from_oos_index(ws: Path) -> list[Clause]:
    path = ws / ".auditooor" / "bug_bounty_oos_index.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: Any
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = (
            payload.get("clauses")
            or payload.get("rows")
            or payload.get("items")
            or payload.get("entries")
            or payload.get("oos_clauses")
            or []
        )
    else:
        rows = []
    if not isinstance(rows, list):
        return []
    clauses: list[Clause] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        phrase = str(
            row.get("phrase")
            or row.get("text")
            or row.get("description")
            or row.get("pattern")
            or row.get("title")
            or ""
        ).strip()
        if len(phrase) < 8:
            continue
        source = str(row.get("source") or row.get("source_path") or ".auditooor/bug_bounty_oos_index.json")
        line = int(row.get("line") or row.get("line_number") or idx)
        clause_id = str(row.get("clause") or row.get("clause_id") or row.get("id") or f"index-row-{idx}")
        clauses.append(
            Clause(
                clause_id=clause_id,
                category=_category_from_index_row(row),
                source=source,
                line=line,
                text=phrase[:500],
                section=str(row.get("section") or row.get("source_section") or "bug_bounty_oos_index"),
            )
        )
    return clauses


def collect_catalog_clauses(ws: Path) -> list[Clause]:
    clauses: list[Clause] = _clauses_from_oos_index(ws)
    for path in _candidate_catalog_paths(ws):
        text = _read_text(path)
        if not text.strip():
            continue
        section = ""
        rel = _rel(path, ws)
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                section = stripped.strip("# ").strip()
                continue
            if not (
                stripped.startswith(("-", "*", "|"))
                or OOS_LINE_RE.search(stripped)
                or AI_FP_RE.search(stripped)
                or KNOWN_RE.search(stripped)
                or DESIGN_RE.search(stripped)
                or ("trust" in stripped.lower() and "assumption" in f"{section} {stripped}".lower())
            ):
                continue
            category = _section_category(path, section, stripped)
            if not category:
                continue
            phrase = re.sub(r"\s+", " ", stripped).strip()
            if len(phrase) < 12:
                continue
            fallback = f"{path.stem}:{idx}"
            clauses.append(
                Clause(
                    clause_id=_extract_clause_id(phrase, fallback),
                    category=category,
                    source=rel,
                    line=idx,
                    text=phrase[:500],
                    section=section,
                )
            )
    return clauses


def _match_clause(candidate_terms: set[str], candidate_text: str, clause: Clause) -> tuple[bool, list[str], float]:
    clause_terms = _tokenize(f"{clause.section} {clause.text}")
    if not candidate_terms or not clause_terms:
        return False, [], 0.0
    overlap = sorted(candidate_terms & clause_terms)
    strong = sorted(set(overlap) & STRONG_MATCH_TOKENS)
    low_candidate = candidate_text.lower()
    low_clause = clause.text.lower()
    if low_candidate and len(low_candidate) >= 8 and low_candidate in low_clause:
        return True, overlap[:10], 0.95
    if strong:
        score = 0.82 if len(strong) == 1 else 0.92
        return True, overlap[:10], score
    if len(overlap) >= 2:
        score = min(0.9, 0.55 + 0.1 * len(overlap))
        return True, overlap[:10], score
    return False, overlap[:10], 0.0


def _severity_oos_terms(ws: Path) -> set[str]:
    terms: set[str] = set()
    for name in ("SEVERITY.md", "SCOPE.md"):
        text = _read_text(ws / name)
        for line in text.splitlines():
            if OOS_LINE_RE.search(line):
                terms.update(_tokenize(line))
    return terms


def _listed_impact_terms(ws: Path) -> set[str]:
    terms: set[str] = set()
    text = _read_text(ws / "SEVERITY.md")
    for line in text.splitlines():
        if not line.strip():
            continue
        if re.search(r"\b(loss|funds|freez|governance|insolv|theft|halt|downtime|liveness|unauthorized|withdraw|mint|dos|denial)\b", line, re.IGNORECASE):
            terms.update(_tokenize(line))
    return terms


def _dryrun_statuses(ws: Path, matches: list[dict[str, Any]], candidate_terms: set[str]) -> dict[str, str]:
    cats = {m["category"] for m in matches}
    severity_terms = _severity_oos_terms(ws)
    impact_terms = _listed_impact_terms(ws)
    if CAT_SEVERITY_OOS in cats or CAT_SCOPE_OOS in cats or (severity_terms and candidate_terms & severity_terms):
        r52 = "fail-program-rubric-oos-match"
    elif impact_terms and not (candidate_terms & impact_terms):
        r52 = "warn-no-verbatim-rubric-row-yet"
    elif not impact_terms:
        r52 = "warn-no-severity-md-impact-rows"
    else:
        r52 = "pass-rubric-row-possible"

    if cats & {CAT_DESIGN, CAT_TRUST, CAT_KNOWN, CAT_SCOPE_OOS, CAT_SEVERITY_OOS}:
        r45 = "fail-designed-as-intended-or-oos-catalog-match"
    else:
        r45 = "pass-no-design-intent-match"

    if cats & {CAT_KNOWN, CAT_PRIOR_ACK}:
        r47 = "fail-acknowledged-known-issue-match"
    else:
        r47 = "pass-no-known-issue-match"

    ai_fp = "fail-ai-fp-catalog-match" if CAT_AI_FP in cats else "pass-no-ai-fp-match"
    return {
        "r52_dryrun": r52,
        "r45_dryrun": r45,
        "r47_dryrun": r47,
        "ai_fp_dryrun": ai_fp,
    }


def find_catalog_matches(ws: Path, candidate: dict[str, Any], *, limit: int = 8) -> list[dict[str, Any]]:
    text = _candidate_text(candidate)
    terms = _tokenize(text)
    matches: list[dict[str, Any]] = []
    for clause in collect_catalog_clauses(ws):
        ok, overlap, confidence = _match_clause(terms, text, clause)
        if not ok:
            continue
        matches.append(
            {
                "clause_id": clause.clause_id,
                "category": clause.category,
                "source": clause.source,
                "line": clause.line,
                "section": clause.section,
                "excerpt": clause.text,
                "overlap_terms": overlap,
                "confidence": round(confidence, 2),
            }
        )
    matches.sort(key=lambda m: (-float(m["confidence"]), str(m["source"]), int(m["line"])))
    return matches[:limit]


def _candidate_test_terms(candidate: dict[str, Any]) -> set[str]:
    terms = _tokenize(_candidate_text(candidate))
    focused = {t for t in terms if t not in STOPWORDS and (len(t) >= 5 or t in IMPORTANT_SHORT_TOKENS)}
    return focused


def scan_existing_pocs(ws: Path, candidate: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    roots = [ws / "poc-tests", ws / "test", ws / "tests"]
    suffixes = {".sol", ".go", ".rs", ".ts", ".js", ".md", ".txt"}
    terms = _candidate_test_terms(candidate)
    if not terms:
        return []
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            path_terms = _tokenize(path.name)
            if not (terms & path_terms) and not any(t in text.lower() for t in sorted(terms)[:24]):
                continue
            file_hits: list[dict[str, Any]] = []
            for idx, line in enumerate(text.splitlines(), start=1):
                line_low = line.lower()
                line_is_negative = bool(NEGATIVE_TEST_RE.search(line))
                if not any(t in line_low for t in terms) and not line_is_negative:
                    continue
                key = (_rel(path, ws), idx)
                if key in seen:
                    continue
                seen.add(key)
                snippet = line.strip()
                negative = bool(NEGATIVE_TEST_RE.search(path.name) or line_is_negative)
                file_hits.append(
                    {
                        "source": key[0],
                        "line": idx,
                        "negative_hint": negative,
                        "excerpt": snippet[:240],
                    }
                )
            if file_hits:
                negative_hits = [hit for hit in file_hits if hit["negative_hint"]]
                hits.append((negative_hits or file_hits)[0])
            if len(hits) >= limit:
                return hits
    return hits[:limit]


def evaluate_preflight(ws: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    candidate_text = _candidate_text(candidate)
    candidate_terms = _tokenize(candidate_text)
    matches = find_catalog_matches(ws, candidate)
    existing_pocs = scan_existing_pocs(ws, candidate)
    dryruns = _dryrun_statuses(ws, matches, candidate_terms)
    failed = [value for value in dryruns.values() if value.startswith("fail-")]
    verdict = "needs-extension-distinct-argument" if failed or matches else "pass-no-oos-catalog-match"
    original_severity = str(candidate.get("severity") or candidate.get("claimed_severity") or "").strip()
    recommended = REDUCED_SEVERITY if verdict == "needs-extension-distinct-argument" else (original_severity or "UNCHANGED")
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "candidate_id": str(candidate.get("id") or candidate.get("candidate_id") or candidate.get("angle_id") or ""),
        "original_severity": original_severity,
        "recommended_severity": recommended,
        "verdict": verdict,
        "dryruns": dryruns,
        "matches": matches,
        "existing_poc_hits": existing_pocs,
        "catalog_clause_count": len(collect_catalog_clauses(ws)),
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines: list[str] = [
        "## Brief-Time OOS / AI-FP / Known-Issue Preflight",
        "",
        f"- Verdict: `{result.get('verdict', 'unknown')}`",
        f"- Original severity: `{result.get('original_severity') or 'unspecified'}`",
        f"- Dispatch severity posture: `{result.get('recommended_severity') or 'UNCHANGED'}`",
    ]
    dryruns = result.get("dryruns") if isinstance(result.get("dryruns"), dict) else {}
    for key in ("r52_dryrun", "r45_dryrun", "r47_dryrun", "ai_fp_dryrun"):
        lines.append(f"- {key}: `{dryruns.get(key, 'not-run')}`")
    lines.append(
        "- Worker instruction: resolve this section before drilling source. "
        "If any matched clause applies, either return `VERDICT: OOS <clause>` "
        "or prove an extension-distinct argument first."
    )
    lines.append("")

    matches = result.get("matches") if isinstance(result.get("matches"), list) else []
    if matches:
        lines.append("### Matched Catalog Clauses")
        lines.append("")
        lines.append("| Source | Clause | Class | Confidence | Match terms | Excerpt |")
        lines.append("|---|---|---|---:|---|---|")
        for m in matches:
            src = f"{m.get('source')}:{m.get('line')}"
            clause = str(m.get("clause_id") or "")
            category = str(m.get("category") or "")
            conf = str(m.get("confidence") or "")
            terms = ", ".join(str(t) for t in (m.get("overlap_terms") or [])[:8])
            excerpt = str(m.get("excerpt") or "").replace("|", "\\|")[:220]
            lines.append(f"| `{src}` | `{clause}` | `{category}` | {conf} | {terms} | {excerpt} |")
        lines.append("")
        lines.append("### Required Extension-Distinct Argument")
        lines.append("")
        lines.append("- Identify the exact catalog assumption this candidate escapes.")
        lines.append("- Cite the file:line or executed PoC assertion that makes it materially different.")
        lines.append("- If the distinction is missing, stop early with `VERDICT: OOS <clause>`.")
        lines.append("")
    else:
        lines.append("_No BUG_BOUNTY / SEVERITY / SCOPE / prior-audit catalog match found for this candidate._")
        lines.append("")

    pocs = result.get("existing_poc_hits") if isinstance(result.get("existing_poc_hits"), list) else []
    lines.append("### Existing PoC / Test Scan")
    lines.append("")
    if pocs:
        lines.append("| Source | Negative hint | Excerpt |")
        lines.append("|---|---|---|")
        for hit in pocs:
            src = f"{hit.get('source')}:{hit.get('line')}"
            neg = "yes" if hit.get("negative_hint") else "no"
            excerpt = str(hit.get("excerpt") or "").replace("|", "\\|")[:220]
            lines.append(f"| `{src}` | `{neg}` | {excerpt} |")
        lines.append("")
        lines.append(
            "If a negative-hint test is relevant, read it before writing a new harness. "
            "The candidate may already be empirically disproven."
        )
    else:
        lines.append("_No existing candidate-specific PoC or test snippet found under `poc-tests/`, `test/`, or `tests/`._")
    lines.append("")
    return "\n".join(lines)


def candidate_from_args(args: argparse.Namespace) -> dict[str, Any]:
    candidate: dict[str, Any] = {}
    if args.candidate_json:
        try:
            parsed = json.loads(args.candidate_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"candidate JSON invalid: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SystemExit("candidate JSON must be an object")
        candidate.update(parsed)
    if args.candidate_text:
        candidate["candidate_text"] = args.candidate_text
    if args.candidate_id:
        candidate["id"] = args.candidate_id
    if args.severity:
        candidate["severity"] = args.severity
    if args.contract:
        candidate["contracts"] = [args.contract]
    if args.file:
        candidate["files"] = [args.file]
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="dispatch brief OOS preflight")
    parser.add_argument("--workspace", required=True, help="Audit workspace path")
    parser.add_argument("--candidate-json", help="Candidate object as JSON")
    parser.add_argument("--candidate-text", help="Candidate text or hypothesis")
    parser.add_argument("--candidate-id", help="Candidate id")
    parser.add_argument("--severity", help="Claimed severity")
    parser.add_argument("--contract", help="Contract or component name")
    parser.add_argument("--file", help="Candidate file path")
    parser.add_argument("--render-md", action="store_true", help="Render markdown")
    parser.add_argument("--json", action="store_true", help="Render JSON")
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    candidate = candidate_from_args(args)
    result = evaluate_preflight(ws, candidate)
    if args.render_md:
        print(render_markdown(result))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
