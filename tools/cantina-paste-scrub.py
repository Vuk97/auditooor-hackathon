#!/usr/bin/env python3
"""cantina-paste-scrub — surgical scrub from paste_ready/ → final_cantina_paste/.

Workaround for `paste-ready-generator.py --triager-paste` which strips
Severity Justification, Likelihood, Override, Source-Only Justification,
Real-Component Precondition, Impact Contract, Scope And Originality, AND
Recommended Fix. Operator caught this in L27 (2026-05-08).

This tool takes a `paste_ready/<finding>.md` as input and emits a
`final_cantina_paste/<finding>.md` that:
- Preserves every section verbatim
- Surgically scrubs internal labels (RG-KILL-*, RG-N6-S1, etc.) and paths
  (agent_outputs/, /Users/wolf/, ~/audits/, etc.)
- Keeps publicly-filed bounty IDs (e.g. RG-01) and commit SHAs
- Verifies title ≤120 chars, scrub-list 0-leak, sections present
- Emits leak-audit JSON for traceability

Schema: auditooor.cantina_paste_scrub.v1
Stdlib-only. Hermetic. Idempotent.

Codified rule reference: docs/CANONICAL_CANTINA_PASTE_TEMPLATE.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

SCHEMA_VERSION = "auditooor.cantina_paste_scrub.v1"

# (regex_pattern, replacement) — applied in order.
SCRUB_RULES: list[tuple[str, str]] = [
    # Workspace-rooted paths (always strip absolute prefix)
    (r"`~/audits/[a-z0-9_-]+/SEVERITY\.md`", "the competition severity rubric"),
    (r"`~/audits/[a-z0-9_-]+/[^`]*`", "the competition documents"),
    (r"/Users/wolf/audits/[a-z0-9_-]+/", ""),
    (r"/Users/wolf/audits/[a-z0-9_-]+", "<workspace>"),
    (r"~/audits/[a-z0-9_-]+/", ""),
    # Internal submission paths
    (r"submissions/paste_ready/[^\s)]*", "the filed submission"),
    (r"submissions/staging/[^\s)]*", "internal staging draft"),
    (r"submissions/held/[^\s)]*", "internal held draft"),
    (r"submissions/internal_sidecars/[^\s)]*", "internal sidecar"),
    # Agent-output / triage references
    (r"`agent_outputs/[^`]*`", "prior internal triage report"),
    (r"agent_outputs/[a-z0-9_./-]+", "internal triage report"),
    # Internal kill / lane references — replace family
    (r"`RG-KILL-(\d+)`", "internal kill report"),
    (r"\(RG-KILL-(\d+)\)", "(internal kill report)"),
    (r"RG-KILL-\d+", "an internal kill report"),
    # Workflow / orchestration jargon
    (r"🚨 KEY FINDING \(operator-attention\)", ""),
    (r"🚨", ""),
    (r"\bTier-[0-9]+\s*\(?[a-z]?\)?", ""),
    (r"\borchestrator session\b", ""),
    (r"\borchestrator\b", ""),
    (r"\bsibling lane\b", "parallel investigation"),
    (r"\bsibling worker\b", "parallel investigation"),
    (r"\bnext-loop\b", ""),
    (r"\bcontext_pack_id\b\s*:\s*[a-zA-Z0-9.:_-]+", ""),
    (r"\bcontext_pack_hash\b\s*:\s*[a-f0-9]+", ""),
    (r"\bMCP receipt\b\s*:.*", ""),
    (r"\bvault_[a-z_]+_context\b", ""),
    (r"\breverted-guard-mine\b", "backward commit-mining"),
    # Internal worker IDs
    (r"\bWorker-[A-Z]+\b", "internal investigation"),
    (r"\bworker-[a-z]+\b", "internal investigation"),
    # Loop iteration tags (L24, L25, etc.) when used as section markers
    (r"\bL\d{1,2}\s+\(operator-caught[^)]*\)\s*:", ""),
    (r"\bcodified L\d{1,2}\b", "codified"),
]

# These INTERNAL_ID patterns receive special handling: replace with "this finding"
# (since they identify the finding being filed, not a public bounty submission).
# Operator must specify which IDs are internal at the CLI; defaults below cover
# the Reserve Governor families operator hit in L25-L27.
DEFAULT_INTERNAL_IDS = [
    r"\bRG-N\d+-S\d+\b",  # RG-N6-S1
    r"\bRG-N\d+\b",  # RG-N6
    r"\bRG-01A\b",
]

# Verification patterns
INTERNAL_LEAK_PATTERNS = [
    (r"\bRG-KILL-\d+\b", "RG-KILL"),
    (r"\bRG-N\d+(-S\d+)?\b", "RG-N*"),
    (r"\bRG-01A\b", "RG-01A"),
    (r"\bWorker-[A-Z]+\b", "Worker-X"),
    (r"\bnext-loop\b", "next-loop"),
    (r"\borchestrator\b", "orchestrator"),
    (r"\bsibling lane\b", "sibling lane"),
    (r"🚨", "🚨"),
]
INTERNAL_PATH_PATTERNS = [
    (r"agent_outputs/", "agent_outputs"),
    (r"/Users/wolf/", "/Users/wolf"),
    (r"~/audits/", "~/audits"),
    (r"submissions/paste_ready/", "submissions/paste_ready"),
    (r"submissions/staging/", "submissions/staging"),
    (r"\.auditooor/", ".auditooor"),
]
REQUIRED_SECTIONS = [
    "## Severity",
    "## Summary",
    "## Root Cause",
    "## Proof of Concept",
]
RECOMMENDED_SECTIONS = [
    "## Severity Justification",
    "## Program Impact Mapping",
    "## Impact Contract",
    "## Production Path",
]
RECOMMENDATION_HEADINGS = ["## Recommendation", "## Recommended Fix"]


def scrub_text(text: str, internal_ids: list[str]) -> str:
    out = text
    for pattern, replacement in SCRUB_RULES:
        out = re.sub(pattern, replacement, out)
    for id_pattern in internal_ids:
        # Replace internal IDs with "this finding" but only when used as a label.
        out = re.sub(id_pattern, "this finding", out)
    # Tidy double-spaces / orphan punctuation introduced by scrubs.
    out = re.sub(r"  +", " ", out)
    out = re.sub(r"\(\s*\)", "", out)
    out = re.sub(r"\s+\.", ".", out)
    out = re.sub(r"\s+,", ",", out)
    return out


def audit_leaks(text: str) -> dict:
    label_hits = {}
    for pattern, name in INTERNAL_LEAK_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            label_hits[name] = len(matches)
    path_hits = {}
    for pattern, name in INTERNAL_PATH_PATTERNS:
        if re.search(pattern, text):
            path_hits[name] = len(re.findall(pattern, text))
    return {"internal_labels": label_hits, "internal_paths": path_hits}


def audit_structure(text: str) -> dict:
    title_line = text.split("\n", 1)[0]
    title = title_line.lstrip("# ").strip()
    title_len_ok = len(title) <= 120
    sections = re.findall(r"^## .+", text, flags=re.MULTILINE)
    have_required = [s for s in REQUIRED_SECTIONS if any(sec.startswith(s) for sec in sections)]
    missing_required = [s for s in REQUIRED_SECTIONS if s not in have_required]
    have_recommended = [s for s in RECOMMENDED_SECTIONS if any(sec.startswith(s) for sec in sections)]
    has_recommendation = any(any(sec.startswith(rec) for sec in sections) for rec in RECOMMENDATION_HEADINGS)
    has_what_tests_prove = "### What the tests prove" in text
    # Verify "What the tests prove" comes AFTER the inline test PASS line
    placement_ok = True
    if has_what_tests_prove:
        suite_idx = text.find("Suite result: ok")
        wtp_idx = text.find("### What the tests prove")
        rec_idx = -1
        for r in RECOMMENDATION_HEADINGS:
            i = text.find(r)
            if i > -1:
                rec_idx = i
                break
        if suite_idx == -1 or wtp_idx == -1:
            placement_ok = False
        else:
            placement_ok = suite_idx < wtp_idx and (rec_idx == -1 or wtp_idx < rec_idx)
    return {
        "title": title,
        "title_chars": len(title),
        "title_len_ok": title_len_ok,
        "sections": sections,
        "have_required": have_required,
        "missing_required": missing_required,
        "have_recommended": have_recommended,
        "has_recommendation": has_recommendation,
        "has_what_tests_prove": has_what_tests_prove,
        "what_tests_prove_placement_ok": placement_ok,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Surgical scrub paste_ready/<finding>.md → final_cantina_paste/<finding>.md"
    )
    ap.add_argument("input", help="paste_ready/<finding>.md (full content)")
    ap.add_argument("output", help="final_cantina_paste/<finding>.md (will be overwritten)")
    ap.add_argument(
        "--internal-id",
        action="append",
        default=None,
        help="Regex pattern for an internal ID to replace with 'this finding'. "
        "Can be repeated. Default: RG-N6-S1, RG-N6, RG-01A.",
    )
    ap.add_argument(
        "--ledger",
        default=None,
        help="Optional path to write the leak-audit JSON. Default: <output>.scrub-ledger.json",
    )
    ap.add_argument("--dry-run", action="store_true", help="Don't write output; just print audit.")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"[error] input not found: {src}", file=sys.stderr)
        return 2
    text = src.read_text(encoding="utf-8")

    internal_ids = args.internal_id or DEFAULT_INTERNAL_IDS
    scrubbed = scrub_text(text, internal_ids)

    leaks_before = audit_leaks(text)
    leaks_after = audit_leaks(scrubbed)
    structure = audit_structure(scrubbed)

    ledger = {
        "schema": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input": str(src),
        "output": args.output,
        "internal_ids_scrubbed": internal_ids,
        "leaks_before": leaks_before,
        "leaks_after": leaks_after,
        "structure_audit": structure,
        "verdict": (
            "clean"
            if (
                not leaks_after["internal_labels"]
                and not leaks_after["internal_paths"]
                and structure["title_len_ok"]
                and not structure["missing_required"]
                and structure["has_recommendation"]
                and (
                    not structure["has_what_tests_prove"]
                    or structure["what_tests_prove_placement_ok"]
                )
            )
            else "review_required"
        ),
    }

    if not args.dry_run:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(scrubbed, encoding="utf-8")

    ledger_path = (
        Path(args.ledger)
        if args.ledger
        else Path(args.output + ".scrub-ledger.json")
    )
    if not args.dry_run:
        ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    # Print human-readable verdict to stderr
    sys.stderr.write(
        f"[{ledger['verdict']}] {src.name} -> {args.output}\n"
        f"  title={structure['title_chars']}c ok={structure['title_len_ok']}\n"
        f"  internal_labels_after={leaks_after['internal_labels'] or 'clean'}\n"
        f"  internal_paths_after={leaks_after['internal_paths'] or 'clean'}\n"
        f"  required_sections={structure['have_required']}\n"
        f"  missing_required={structure['missing_required'] or 'none'}\n"
        f"  has_recommendation={structure['has_recommendation']}\n"
        f"  what_tests_prove_placement_ok={structure['what_tests_prove_placement_ok']}\n"
    )
    return 0 if ledger["verdict"] == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())
