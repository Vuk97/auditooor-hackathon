#!/usr/bin/env python3
"""
finding-quality-scorer.py — Predictive quality scoring for submission drafts

Rates a draft on 6 dimensions and outputs an acceptance-likelihood score (0-100):
  1. PoC Quality (0-20): compiles? shows value movement? has asserts?
  2. Description Clarity (0-20): file:line citations? specific code paths?
  3. Impact Specificity (0-20): dollar impact? TVL reference? realistic trigger?
  4. Rubric Alignment (0-15): cites rubric? maps to severity justification?
  5. Originality Defense (0-15): originality check? distinction paragraph?
  6. Severity Justification (0-10): why this severity? not theoretical?

Usage:
    finding-quality-scorer.py <workspace> <draft.md>
    finding-quality-scorer.py ~/audits/polymarket ~/audits/polymarket/submissions/staging/my-draft.md
    finding-quality-scorer.py <ws> <draft> --json

Exit codes:
    0 — score >= 70 (strong draft)
    1 — score 40-69 (needs work)
    2 — score < 40 (weak draft, likely rejected)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def score_poc_quality(text: str, draft_path: Path, ws: Path) -> Tuple[int, List[str]]:
    """Score PoC quality (0-20)."""
    score = 0
    notes = []
    
    # Check for PoC reference. Solidity drafts usually cite *.t.sol; Rust/DLT
    # drafts cite cargo-test harnesses under poc-tests/<name>/Cargo.toml or
    # checked-in run logs.
    poc_refs = re.findall(
        r'[a-zA-Z0-9_./-]+\.t\.sol|poc-tests/[a-zA-Z0-9_./-]+/(?:Cargo\.toml|[a-zA-Z0-9_.-]+\.rs|[a-zA-Z0-9_.-]+\.log)',
        text,
        re.I,
    )
    if poc_refs:
        score += 5
        notes.append(f"PoC referenced: {poc_refs[0]}")
    else:
        notes.append("No PoC test referenced")
    
    # Check for forge/cargo test output
    if re.search(r'forge test|cargo test|test result:\s+ok|passed|failed|\[PASS\]|\[FAIL\]', text, re.I):
        score += 5
        notes.append("Execution output included")
    else:
        notes.append("No forge/cargo test output")
    
    # Check for value movement assertions
    if re.search(
        r'assertEq.*balance|assertGt.*balance|extracted|profit|loss|state.*corrupt|'
        r'output[_ -]?root|rootClaim|withdrawals[_ -]?root|chain split|finali[sz]ation',
        text,
        re.I,
    ):
        score += 5
        notes.append("Impact/state assertions present")
    else:
        notes.append("No value/state assertions")
    
    # Check if PoC file actually exists
    if poc_refs:
        poc_name = poc_refs[0]
        candidates = [ws / poc_name, ws / "poc-tests" / Path(poc_name).name]
        if any(path.exists() for path in candidates):
            score += 5
            notes.append("PoC artifact exists on disk")
        else:
            notes.append("PoC artifact not found on disk")
    
    return min(20, score), notes


def score_description_clarity(text: str) -> Tuple[int, List[str]]:
    """Score description clarity (0-20)."""
    score = 0
    notes = []
    
    # File:line citations
    citations = re.findall(
        r'[A-Za-z_][A-Za-z0-9_./-]*\.(?:sol|rs|go|circom):\d+|'
        r'[A-Za-z_][A-Za-z0-9_./-]*\.(?:sol|rs|go|circom)#L\d+',
        text,
    )
    if len(citations) >= 3:
        score += 8
        notes.append(f"Strong file:line citations ({len(citations)} refs)")
    elif len(citations) >= 1:
        score += 4
        notes.append(f"Some citations ({len(citations)} refs)")
    else:
        notes.append("No file:line citations")
    
    # Specific code paths described
    if re.search(r'function\s+\w+.*calls?|step\s+\d|sequence|attack path', text, re.I):
        score += 6
        notes.append("Specific code paths described")
    else:
        notes.append("Code paths not clearly described")
    
    # Concrete trigger (not theoretical)
    if re.search(r'concrete|specific|exact|step-by-step| PoC ', text, re.I):
        score += 6
        notes.append("Concrete trigger described")
    else:
        notes.append("Trigger may be too abstract")
    
    return min(20, score), notes


def score_impact_specificity(text: str) -> Tuple[int, List[str]]:
    """Score impact specificity (0-20)."""
    score = 0
    notes = []
    
    # Dollar impact
    if re.search(r'\$[0-9]+[KkMmBb]?|USDC|TVL|[0-9]+[KkMmBb] (at risk|of funds|loss)', text):
        score += 8
        notes.append("Dollar impact quantified")
    else:
        notes.append("No dollar impact quantified")
    
    # Realistic trigger
    if re.search(r'realistic|token supply|max supply|total supply|achievable', text, re.I):
        score += 6
        notes.append("Realistic trigger bounds documented")
    else:
        notes.append("No realistic bounds documented")
    
    # Victim impact
    if re.search(r'user|depositor|trader|attacker can|victim', text, re.I):
        score += 6
        notes.append("Victim/attacker roles defined")
    else:
        notes.append("Victim impact not clearly defined")
    
    return min(20, score), notes


def score_rubric_alignment(text: str) -> Tuple[int, List[str]]:
    """Score rubric alignment (0-15)."""
    score = 0
    notes = []
    
    # Rubric citation
    if re.search(r'rubric|impact example|severity justification|maps to|this matches', text, re.I):
        score += 8
        notes.append("Rubric cited")
    else:
        notes.append("No rubric citation")
    
    # Severity justification
    if re.search(r'severity.*because|justification|reason.*(high|medium|low|critical)', text, re.I):
        score += 7
        notes.append("Severity justified")
    else:
        notes.append("Severity not well-justified")
    
    return min(15, score), notes


def score_originality_defense(text: str) -> Tuple[int, List[str]]:
    """Score originality defense (0-15)."""
    score = 0
    notes = []
    
    # Originality check referenced
    if re.search(r'originality|grep.*audit|prior audit|dupe check|corpus', text, re.I):
        score += 5
        notes.append("Originality check referenced")
    else:
        notes.append("No originality check reference")
    
    # Distinction paragraph (for near-variants)
    if re.search(r'distinction|different vector|novel|not a dupe|this differs', text, re.I):
        score += 5
        notes.append("Distinction/defense paragraph present")
    else:
        notes.append("No distinction paragraph")
    
    # Not purely theoretical
    if not re.search(r'theoretically|in theory|could potentially|might be possible', text, re.I):
        score += 5
        notes.append("Language is concrete (not theoretical)")
    else:
        notes.append("Theoretical language detected")
    
    return min(15, score), notes


def score_severity_justification(text: str) -> Tuple[int, List[str]]:
    """Score severity justification (0-10)."""
    score = 0
    notes = []
    
    # Severity explicitly stated
    sev_match = re.search(
        r'(?:\*\*)?Severity(?:\s*\([^)]*\))?(?:\*\*)?\s*[:|-]\s*(?:\*\*)?(Critical|High|Medium|Low)',
        text,
        re.I,
    )
    if sev_match:
        score += 3
        notes.append(f"Severity stated: {sev_match.group(1)}")
    else:
        notes.append("Severity not explicitly stated")
    
    # Privileged attacker addressed (if applicable)
    if re.search(r'operator|admin|owner|privileged|sequencer|signer|governance', text, re.I):
        if re.search(
            r'permissionless|any user|unauthorized|no role|no private key compromise|'
            r'not rely on privileged|without privileged|normal in-scope|in-scope Engine API',
            text,
            re.I,
        ):
            score += 4
            notes.append("Privileged attacker constraint addressed")
        else:
            notes.append("Privileged attacker mentioned but not addressed")
    else:
        score += 4
        notes.append("No privileged attacker requirement")
    
    # Not event-only
    if re.search(r'state.*corrupt|fund.*loss|balance.*change|transfer|drain', text, re.I):
        score += 3
        notes.append("State/fund impact described (not event-only)")
    else:
        notes.append("May be event-only — verify state impact")
    
    return min(10, score), notes


def main() -> None:
    parser = argparse.ArgumentParser(description="Finding quality scorer")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("draft", help="Draft submission file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    draft_path = Path(args.draft).expanduser().resolve()
    
    if not ws.exists():
        print(f"[scorer] Workspace not found: {ws}")
        sys.exit(1)
    if not draft_path.exists():
        print(f"[scorer] Draft not found: {draft_path}")
        sys.exit(1)

    text = draft_path.read_text()
    
    # Score all dimensions
    dimensions = {}
    all_notes = []
    
    s, n = score_poc_quality(text, draft_path, ws)
    dimensions["poc_quality"] = {"score": s, "max": 20, "notes": n}
    all_notes.extend(n)
    
    s, n = score_description_clarity(text)
    dimensions["description_clarity"] = {"score": s, "max": 20, "notes": n}
    all_notes.extend(n)
    
    s, n = score_impact_specificity(text)
    dimensions["impact_specificity"] = {"score": s, "max": 20, "notes": n}
    all_notes.extend(n)
    
    s, n = score_rubric_alignment(text)
    dimensions["rubric_alignment"] = {"score": s, "max": 15, "notes": n}
    all_notes.extend(n)
    
    s, n = score_originality_defense(text)
    dimensions["originality_defense"] = {"score": s, "max": 15, "notes": n}
    all_notes.extend(n)
    
    s, n = score_severity_justification(text)
    dimensions["severity_justification"] = {"score": s, "max": 10, "notes": n}
    all_notes.extend(n)
    
    total = sum(d["score"] for d in dimensions.values())
    max_total = sum(d["max"] for d in dimensions.values())
    
    if total >= 70:
        quality = "STRONG"
        exit_code = 0
    elif total >= 40:
        quality = "NEEDS_WORK"
        exit_code = 1
    else:
        quality = "WEAK"
        exit_code = 2
    
    if args.json:
        output = {
            "draft": str(draft_path),
            "total_score": total,
            "max_score": max_total,
            "quality": quality,
            "dimensions": dimensions,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"Finding Quality Score: {total}/{max_total} — {quality}")
        print(f"{'='*70}")
        print()
        for name, data in dimensions.items():
            pct = (data["score"] / data["max"]) * 100
            bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
            print(f"{name.replace('_', ' ').title():25} {bar} {data['score']}/{data['max']}")
            for note in data["notes"]:
                print(f"  → {note}")
            print()
        
        print(f"{'='*70}")
        if quality == "STRONG":
            print("✅ Strong draft — proceed to pre-submit-check and submit")
        elif quality == "NEEDS_WORK":
            print("⚠️  Needs work — address the flagged issues before submitting")
        else:
            print("❌ Weak draft — high rejection risk. Major improvements needed.")
        print(f"{'='*70}")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
