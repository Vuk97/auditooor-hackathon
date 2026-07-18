#!/usr/bin/env python3
"""prior-audit-dupe-gate.py — L31 prior-audit adjacency gate for staging drafts.

Empirical anchor (2026-05-22 Hyperbridge hunt): a staging Low for a
call-decompressor size-cap bypass was only caught as a DUPLICATE of SRL
ISMP-baseline finding 6.10 (risk-accepted by the team) when an external
reviewer pushed for a dupe-preflight. The hunt agent had done a PROSE
"originality vs the SRL audits" check, not a mechanical one. This gate
closes that gap: it forces a machine check of every staging draft against
the engagement's prior audit reports BEFORE the draft counts as
staging-ready.

Verdict vocabulary (per draft):
  clear               - no prior-audit text overlaps the draft's component
                        tokens. Safe to proceed without an originality section.
  adjacent-review     - a prior finding's component tokens overlap the draft's
                        component tokens. The draft MUST contain an explicit
                        ## Duplicate Preflight / ## Originality section that
                        names the specific prior finding and argues distinctness
                        (L31 Q1/Q2). Gate FAILS if the section is absent.
  likely-dupe         - a prior finding overlaps the draft on BOTH component
                        AND impact class. High dupe risk. Gate FAILS unless an
                        explicit dupe-preflight section is present.
  no-prior-audits     - no prior_audits/ directory or no readable prior-audit
                        files found. Gate passes (no comparison possible).
  no-staging-drafts   - no staging drafts found (or --draft not found). Pass.

Usage:
    prior-audit-dupe-gate.py --workspace <ws>
        [--draft <path>]       single draft override
        [--queue <path>]       source-mined/exploit queue rows to check
        [--top-n N]            max queue rows to check
        [--strict]             exit non-zero on likely-dupe or adjacent-review
                               WITHOUT a dupe-preflight section
        [--json]               machine-readable JSON output
        [--min-token-overlap N] minimum shared component tokens to flag
                               adjacent-review (default 1)

Exit codes:
    0  all drafts clear or have valid originality sections
    1  at least one draft is likely-dupe or adjacent-review without section
    2  no prior audits found (advisory, gate passes)
    3  configuration / parse error

Schema: auditooor.prior_audit_dupe_gate.v1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.prior_audit_dupe_gate.v1"
TERMINAL_STATES = {
    "advisory",
    "advisory_only",
    "duplicate",
    "dupe",
    "false_positive",
    "killed",
    "negative",
    "not_a_bug",
    "not_candidate",
    "oos",
    "out_of_scope",
    "rejected",
    "terminal",
    "terminal_no_submission",
}

# ---------------------------------------------------------------------------
# Component token extraction
# ---------------------------------------------------------------------------

# Match pallet names (Substrate), contract names, filenames (without path),
# function names in backtick code spans, and bare CamelCase identifiers.
BACKTICK_TOKEN_RE = re.compile(r"`([^`\n]{2,60})`")
# Require genuine CamelCase (at least one lowercase letter followed by an
# uppercase interior transition), so plain title-case words like "Missing",
# "Risk", "The" are excluded.
CAMEL_IDENT_RE = re.compile(r"\b([A-Z][a-z]+(?:[A-Z][a-zA-Z0-9]+)+)\b")
FILE_TOKEN_RE = re.compile(
    r"\b([a-zA-Z0-9_-]{3,}\.(?:sol|go|rs|ts|tsx|py|js|move|cairo|vy|fc))"
    r"(?::\d+(?:-\d+)?)?\b"
)
PALLET_TOKEN_RE = re.compile(r"\bpallet[-_]([a-z][a-z0-9_-]{2,})\b", re.IGNORECASE)
MODULE_TOKEN_RE = re.compile(r"\b([a-z][a-z0-9_]{3,})::[A-Za-z]")

# Impact class keywords — coarse taxonomy matching the L31 Q2 axis.
# A prior-audit finding and a draft share an impact class if they share
# at least one keyword from this list.
IMPACT_CLASS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dos", re.compile(r"\b(?:dos|denial.of.service|resource.exhaust|hang|stall|grief)\b", re.I)),
    ("overflow", re.compile(r"\b(?:overflow|underflow|arithmetic|integer.overflow)\b", re.I)),
    ("reentrancy", re.compile(r"\b(?:reentr(?:ancy|ant)|re-entr|reentr)\b", re.I)),
    ("access-control", re.compile(r"\b(?:access.control|unauthorized|privilege|permis(?:sion|sioned)|auth(?:orization)?)\b", re.I)),
    ("fund-loss", re.compile(r"\b(?:loss.of.funds?|theft|drain|steal|fund.loss|direct.loss|locked.funds?|freeze)\b", re.I)),
    ("validation", re.compile(r"\b(?:missing.check|missing.validation|input.validation|bounds.check|size.check|size.cap)\b", re.I)),
    ("logic", re.compile(r"\b(?:logic.error|incorrect.logic|wrong.(?:check|computation)|miscalculation)\b", re.I)),
    ("storage", re.compile(r"\b(?:storage.collision|storage.slot|slot.clash|mapping.collision)\b", re.I)),
]

# Originality / dupe-preflight section detector.
ORIGINALITY_SECTION_RE = re.compile(
    r"^#{1,3}\s+(?:duplicate\s+preflight|originality|dupe\s+preflight|"
    r"prior.audit|duplicate.check|prior.finding)",
    re.IGNORECASE | re.MULTILINE,
)

# Prior-audit finding header detector (looks for numbered / bulleted findings
# inside prior audit text, e.g. "6.10 Call Decompressor ..." or "Finding: ...").
PRIOR_FINDING_HEADER_RE = re.compile(
    r"(?:^|\n)\s*(?:\d+\.\d+|\d+\)|\*|[-])\s+(.{5,120})",
)

# Inline dupe-preflight rebuttal marker (same spirit as l31-rebuttal).
PRIOR_AUDIT_REBUTTAL_RE = re.compile(
    r"<!--\s*prior-audit-dupe-rebuttal:\s*(.+?)\s*-->",
    re.DOTALL | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(p: Path) -> str:
    """Read a file, returning empty string on any error."""
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _norm(value: Any, *, limit: int = 2000) -> str:
    if isinstance(value, (list, tuple, set)):
        value = "\n".join(_norm(item, limit=limit) for item in value)
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _status_key(value: Any) -> str:
    text = _norm(value, limit=120).lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _extract_component_tokens(text: str) -> set[str]:
    """Extract heuristic component tokens from markdown text."""
    tokens: set[str] = set()

    # Backtick spans (function names, identifiers, short paths)
    for m in BACKTICK_TOKEN_RE.finditer(text):
        val = m.group(1).strip()
        # Keep reasonably-specific tokens (not single chars, not full sentences)
        if 3 <= len(val) <= 80 and " " not in val:
            tokens.add(val.lower())
        elif 3 <= len(val) <= 80:
            # Multi-word backtick span: keep the individual words too
            for w in val.split():
                if len(w) >= 3:
                    tokens.add(w.lower())

    # File tokens (e.g. call_decompressor.rs, ismp.go)
    for m in FILE_TOKEN_RE.finditer(text):
        tokens.add(m.group(1).lower())

    # Pallet tokens (Substrate: pallet-ismp, pallet-hyperbridge)
    for m in PALLET_TOKEN_RE.finditer(text):
        tokens.add(f"pallet-{m.group(1).lower()}")
        tokens.add(m.group(1).lower())

    # Rust module path prefix (e.g. ismp::, hyperbridge::)
    for m in MODULE_TOKEN_RE.finditer(text):
        tokens.add(m.group(1).lower())

    # CamelCase identifiers (contract / pallet / struct names)
    for m in CAMEL_IDENT_RE.finditer(text):
        tokens.add(m.group(1).lower())

    # Remove very generic tokens that appear everywhere
    NOISE = {
        "the", "and", "for", "with", "this", "that", "from", "not", "can",
        "use", "are", "has", "its", "any", "all", "may", "bug", "fix",
        "note", "see", "via", "per", "low", "high", "med", "audit",
        "none", "new", "old", "get", "set", "run", "let",
    }
    tokens -= NOISE
    return tokens


def _extract_impact_classes(text: str) -> set[str]:
    """Return the set of coarse impact class labels present in text."""
    hits: set[str] = set()
    for label, pat in IMPACT_CLASS_PATTERNS:
        if pat.search(text):
            hits.add(label)
    return hits


def _has_originality_section(text: str) -> bool:
    """True if the draft contains an explicit dupe-preflight/originality section."""
    return bool(ORIGINALITY_SECTION_RE.search(text))


def _has_rebuttal_marker(text: str) -> bool:
    """True if an explicit prior-audit-dupe-rebuttal HTML comment is present."""
    m = PRIOR_AUDIT_REBUTTAL_RE.search(text)
    return bool(m and m.group(1).strip())


def _gather_prior_audits(ws: Path) -> list[dict[str, Any]]:
    """Find and read prior audit texts from the workspace.

    Searches:
      <ws>/prior_audits/*.txt
      <ws>/prior_audits/*.md
      <ws>/src/**/audits/*.txt  (for in-tree audit placement)
      <ws>/src/**/audits/*.md
    Returns a list of dicts: {path, text, tokens, impacts}
    """
    dirs_to_search: list[Path] = []
    pa_dir = ws / "prior_audits"
    if pa_dir.is_dir():
        dirs_to_search.append(pa_dir)

    # Scan src/**/audits/
    src_dir = ws / "src"
    if src_dir.is_dir():
        for candidate in src_dir.rglob("audits"):
            if candidate.is_dir():
                dirs_to_search.append(candidate)

    prior_audits: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for d in dirs_to_search:
        for ext in ("*.txt", "*.md"):
            for p in sorted(d.glob(ext)):
                rp = p.resolve()
                if rp in seen:
                    continue
                seen.add(rp)
                text = _read_text(p)
                if not text.strip():
                    continue
                prior_audits.append({
                    "path": str(p),
                    "name": p.name,
                    "text": text,
                    "tokens": _extract_component_tokens(text),
                    "impacts": _extract_impact_classes(text),
                })
    return prior_audits


def _gather_staging_drafts(ws: Path, draft_override: Path | None) -> list[Path]:
    """Return list of staging draft paths to evaluate."""
    if draft_override is not None:
        if draft_override.is_file():
            return [draft_override]
        return []
    staging_dir = ws / "submissions" / "staging"
    if not staging_dir.is_dir():
        return []
    return sorted(staging_dir.glob("*.md"))


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("queue", "rows", "candidates", "leads", "items", "packets"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _is_terminal_row(row: dict[str, Any]) -> bool:
    if row.get("row_is_advisory") is True or row.get("advisory_only") is True:
        return True
    for key in (
        "proof_status",
        "quality_gate_status",
        "status",
        "packet_state",
        "scope_status",
        "verdict",
        "execution_contract_claim",
    ):
        if _status_key(row.get(key)) in TERMINAL_STATES:
            return True
    return False


def _gather_queue_rows(queue_path: Path, top_n: int | None) -> list[dict[str, Any]]:
    payload = _read_json(queue_path)
    rows = [row for row in _rows_from_payload(payload) if not _is_terminal_row(row)]
    if top_n is not None:
        return rows[:top_n]
    return rows


def _row_id(row: dict[str, Any]) -> str:
    for key in ("lead_id", "candidate_id", "row_id", "id", "packet_id", "title"):
        value = _norm(row.get(key), limit=200)
        if value:
            return value
    return "candidate"


def _row_originality_text(row: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "duplicate_preflight",
        "dupe_preflight",
        "originality",
        "originality_section",
        "originality_rationale",
        "prior_audit_distinctness",
        "prior_audit_rebuttal",
        "prior_disclosure_rebuttal",
        "dupe_rebuttal",
        "duplicate_rebuttal",
    ):
        value = _norm(row.get(key), limit=2000)
        if value:
            values.append(value)
    return "\n".join(values)


def _row_to_dupe_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "lead_id",
        "candidate_id",
        "row_id",
        "id",
        "title",
        "component",
        "contract",
        "contract_name",
        "function",
        "function_name",
        "function_signature",
        "entrypoint",
        "attack_class",
        "source_refs",
        "source_artifacts",
        "evidence_refs",
        "source_citations",
        "selected_impact",
        "listed_impact_selected",
        "impact_path",
        "root_cause_hypothesis",
        "prior_disclosure_triple",
        "dupe_triple",
    ):
        value = _norm(row.get(key), limit=2000)
        if value:
            parts.append(f"{key}: {value}")
    originality = _row_originality_text(row)
    if originality:
        parts.append(f"## Originality\n{originality}")
    return "\n".join(parts)


def _split_prior_audit_into_findings(prior: dict[str, Any]) -> list[dict[str, Any]]:
    """Split a prior-audit text into individual finding blocks (best-effort).

    We heuristically split on numbered section headers (e.g. "6.10 Title"),
    lettered findings, or "## Finding" headers. Each finding block is then
    independently tokenised so we can report which finding triggered.
    """
    text = prior["text"]
    # Try to split on lines that look like finding headers.
    # We join each segment with the header line.
    splitter = re.compile(
        r"(?:^|\n)"
        r"(?:"
        r"\d+\.\d+\s+[A-Z]"          # 6.10 Title
        r"|Finding\s+#?\d+"           # Finding #1
        r"|#{1,4}\s+(?:Finding|Issue|Vulnerability|Bug|Risk)\b"
        r"|[A-Z]-\d+[:\s]"            # A-01: Title
        r"|\[\w+\]\s+[A-Z]"           # [H-01] Title
        r")",
        re.IGNORECASE,
    )
    positions = [m.start() for m in splitter.finditer(text)]
    if len(positions) < 2:
        # Cannot split - treat whole document as one "finding"
        return [prior]

    findings: list[dict[str, Any]] = []
    positions.append(len(text))
    for i in range(len(positions) - 1):
        block = text[positions[i]:positions[i + 1]]
        if len(block.strip()) < 30:
            continue
        # Extract a title from the first line
        first_line = block.lstrip("\n").split("\n")[0].strip()[:120]
        findings.append({
            "path": prior["path"],
            "name": prior["name"],
            "title": first_line,
            "text": block,
            "tokens": _extract_component_tokens(block),
            "impacts": _extract_impact_classes(block),
        })
    return findings if findings else [prior]


def _check_text(
    *,
    name: str,
    text: str,
    prior_audits: list[dict[str, Any]],
    min_overlap: int,
    item_label: str,
) -> dict[str, Any]:
    """Run the adjacency check for arbitrary candidate text against prior audits."""
    draft_tokens = _extract_component_tokens(text)
    draft_impacts = _extract_impact_classes(text)
    has_orig_section = _has_originality_section(text)
    has_rebuttal = _has_rebuttal_marker(text)

    adjacencies: list[dict[str, Any]] = []

    for prior in prior_audits:
        for finding in _split_prior_audit_into_findings(prior):
            shared_tokens = draft_tokens & finding["tokens"]
            if len(shared_tokens) < min_overlap:
                continue
            shared_impacts = draft_impacts & finding["impacts"]
            adjacencies.append({
                "prior_file": finding.get("path", prior["path"]),
                "prior_finding_title": finding.get("title", finding.get("name", "")),
                "shared_component_tokens": sorted(shared_tokens),
                "shared_impact_classes": sorted(shared_impacts),
                "overlap_token_count": len(shared_tokens),
                "overlap_impact_count": len(shared_impacts),
            })

    if not adjacencies:
        verdict = "clear"
        gate_pass = True
        reason = "No prior-audit component overlap detected."
    else:
        # Classify by worst adjacency
        likely_dupes = [a for a in adjacencies if a["overlap_impact_count"] >= 1]
        if likely_dupes:
            verdict = "likely-dupe"
            worst = max(likely_dupes, key=lambda a: a["overlap_token_count"] + a["overlap_impact_count"] * 3)
        else:
            verdict = "adjacent-review"
            worst = max(adjacencies, key=lambda a: a["overlap_token_count"])

        if has_orig_section or has_rebuttal:
            gate_pass = True
            reason = (
                "Dupe-preflight section / rebuttal marker present - "
                "adjacency addressed by author."
            )
        else:
            gate_pass = False
            reason = (
                f"{item_label} has {verdict} adjacency with prior audit "
                f"('{worst['prior_finding_title'][:80]}' in "
                f"{Path(worst['prior_file']).name}) but no "
                f"'## Duplicate Preflight' / '## Originality' section."
            )

    return {
        "draft": name,
        "draft_name": name,
        "verdict": verdict,
        "gate_pass": gate_pass,
        "reason": reason,
        "has_originality_section": has_orig_section,
        "has_rebuttal_marker": has_rebuttal,
        "adjacencies": adjacencies,
        "draft_component_tokens_count": len(draft_tokens),
        "draft_impact_classes": sorted(draft_impacts),
    }


def _check_draft(
    draft_path: Path,
    prior_audits: list[dict[str, Any]],
    min_overlap: int,
) -> dict[str, Any]:
    """Run the adjacency check for a single draft against all prior audits."""
    result = _check_text(
        name=draft_path.name,
        text=_read_text(draft_path),
        prior_audits=prior_audits,
        min_overlap=min_overlap,
        item_label="Draft",
    )
    result["draft"] = str(draft_path)
    return result


def _check_row(
    row: dict[str, Any],
    prior_audits: list[dict[str, Any]],
    min_overlap: int,
) -> dict[str, Any]:
    row_name = _row_id(row)
    result = _check_text(
        name=row_name,
        text=_row_to_dupe_text(row),
        prior_audits=prior_audits,
        min_overlap=min_overlap,
        item_label="Queue row",
    )
    result["lead_id"] = row_name
    result["candidate_id"] = _norm(row.get("candidate_id"), limit=200) or row_name
    result["row_title"] = _norm(row.get("title"), limit=300)
    result["row_source"] = "queue"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prior-audit adjacency gate for staging drafts (L31 extension).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--workspace", "-w", required=True, help="Workspace root path")
    parser.add_argument(
        "--draft", "-d", default=None,
        help="Single draft to check (overrides staging/ scan)"
    )
    parser.add_argument(
        "--queue", "-q", default=None,
        help="Exploit/source-mined queue JSON to check instead of staging drafts"
    )
    parser.add_argument(
        "--top-n", type=int, default=None, metavar="N",
        help="Maximum non-terminal queue rows to check"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero on any adjacent-review or likely-dupe without originality section"
    )
    parser.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Emit machine-readable JSON"
    )
    parser.add_argument(
        "--min-token-overlap", type=int, default=1, metavar="N",
        help="Minimum shared component tokens to flag adjacent-review (default 1)"
    )
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"ERROR: workspace directory not found: {ws}", file=sys.stderr)
        return 3

    draft_override: Path | None = None
    if args.draft:
        draft_override = Path(args.draft).expanduser().resolve()
    queue_path: Path | None = None
    if args.queue:
        queue_path = Path(args.queue).expanduser().resolve()
    if draft_override is not None and queue_path is not None:
        print("ERROR: --draft and --queue are mutually exclusive", file=sys.stderr)
        return 3

    queue_rows: list[dict[str, Any]] = []
    if queue_path is not None:
        if not queue_path.is_file():
            print(f"ERROR: queue file not found: {queue_path}", file=sys.stderr)
            return 3
        try:
            queue_rows = _gather_queue_rows(queue_path, args.top_n)
        except json.JSONDecodeError as exc:
            print(
                f"ERROR: malformed queue JSON: {queue_path}: "
                f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
                file=sys.stderr,
            )
            return 3
        except OSError as exc:
            print(f"ERROR: unable to read queue file: {queue_path}: {exc}", file=sys.stderr)
            return 3

    # Gather prior audits
    prior_audits = _gather_prior_audits(ws)
    if not prior_audits:
        result = {
            "schema": SCHEMA_VERSION,
            "workspace": str(ws),
            "mode": "queue" if queue_path is not None else "draft",
            "verdict_summary": "no-prior-audits",
            "gate_pass": True,
            "prior_audit_count": 0,
            "drafts": [],
            "message": "No prior audit files found in prior_audits/ or src/**/audits/. Gate passes.",
        }
        if args.json_out:
            print(json.dumps(result, indent=2))
        else:
            print("[prior-audit-dupe-gate] PASS (no-prior-audits): no prior audit files found.")
        return 2

    # Gather staging drafts or queue rows.
    draft_paths: list[Path] = []
    if queue_path is None:
        draft_paths = _gather_staging_drafts(ws, draft_override)

    if queue_path is not None and not queue_rows:
        result = {
            "schema": SCHEMA_VERSION,
            "workspace": str(ws),
            "mode": "queue",
            "queue": str(queue_path),
            "verdict_summary": "no-queue-rows",
            "gate_pass": True,
            "prior_audit_count": len(prior_audits),
            "row_count": 0,
            "drafts": [],
            "message": "No non-terminal queue rows found. Gate passes.",
        }
        if args.json_out:
            print(json.dumps(result, indent=2))
        else:
            print("[prior-audit-dupe-gate] PASS (no-queue-rows): no queue rows to check.")
        return 0

    if queue_path is None and not draft_paths:
        result = {
            "schema": SCHEMA_VERSION,
            "workspace": str(ws),
            "mode": "draft",
            "verdict_summary": "no-staging-drafts",
            "gate_pass": True,
            "prior_audit_count": len(prior_audits),
            "drafts": [],
            "message": "No staging drafts found. Gate passes.",
        }
        if args.json_out:
            print(json.dumps(result, indent=2))
        else:
            print("[prior-audit-dupe-gate] PASS (no-staging-drafts): no staging drafts to check.")
        return 0

    # Run checks
    draft_results: list[dict[str, Any]] = []
    if queue_path is not None:
        for row in queue_rows:
            draft_results.append(_check_row(row, prior_audits, args.min_token_overlap))
    else:
        for dp in draft_paths:
            draft_results.append(_check_draft(dp, prior_audits, args.min_token_overlap))

    # Determine overall gate pass
    failures = [r for r in draft_results if not r["gate_pass"]]
    overall_pass = len(failures) == 0

    # Build summary
    verdict_counts: dict[str, int] = {}
    for r in draft_results:
        verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1

    result = {
        "schema": SCHEMA_VERSION,
        "workspace": str(ws),
        "mode": "queue" if queue_path is not None else "draft",
        "verdict_summary": "pass" if overall_pass else "fail",
        "gate_pass": overall_pass,
        "prior_audit_count": len(prior_audits),
        "draft_count": len(draft_results),
        "row_count": len(draft_results) if queue_path is not None else 0,
        "queue": str(queue_path) if queue_path is not None else None,
        "verdict_counts": verdict_counts,
        "failures": len(failures),
        "drafts": draft_results,
    }

    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        _human_output(result, failures)

    if args.strict and not overall_pass:
        return 1
    if not overall_pass:
        return 1
    return 0


def _human_output(result: dict[str, Any], failures: list[dict[str, Any]]) -> None:
    gate = "PASS" if result["gate_pass"] else "FAIL"
    print(
        f"[prior-audit-dupe-gate] {gate} | "
        f"{result['prior_audit_count']} prior-audit file(s) | "
        f"{result['draft_count']} draft(s) | "
        f"verdicts: {result['verdict_counts']}"
    )
    for dr in result["drafts"]:
        icon = "OK" if dr["gate_pass"] else "FAIL"
        print(f"  [{icon}] {dr['draft_name']}: {dr['verdict']} - {dr['reason']}")
        if not dr["gate_pass"]:
            for adj in dr["adjacencies"][:3]:
                print(
                    f"        overlap: tokens={adj['shared_component_tokens'][:5]} "
                    f"impacts={adj['shared_impact_classes']} "
                    f"prior='{adj['prior_finding_title'][:60]}'"
                )
    if failures:
        print()
        print("REQUIRED ACTION: add '## Duplicate Preflight' section to each FAIL draft,")
        print("naming the prior finding and arguing L31 Q1/Q2 distinctness.")


if __name__ == "__main__":
    sys.exit(main())
