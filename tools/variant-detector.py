#!/usr/bin/env python3
"""
Semantic dupe/near-variant detector against workspace submission ledgers or sibling staging drafts.

Compares a draft submission against the workspace submission ledger (or sibling
staging drafts as fallback) using multiple signals:
  1. Contract/function exact match (weight: 40%)
  2. Bug class overlap (weight: 25%)
  3. Impact description semantic similarity (weight: 20%)
  4. Code path distinctness (weight: 15%)

Outputs a dupe-risk score (0-100) with detailed rationale.

Usage:
    variant-detector.py <workspace> <draft.md>
    variant-detector.py ~/audits/<project> ~/audits/<project>/submissions/staging/<draft>.md
    variant-detector.py <ws> <draft> --json

Exit codes:
    0 — low dupe risk (< 30)
    1 — medium dupe risk (30-69)
    2 — high dupe risk (>= 70)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from submission_ledger import is_prior_submission_status, load_submission_entries_from_text
from submission_paths import find_submission_file


SKIP_DRAFT_SUFFIXES = (".block.md", ".notes.md")


def load_submissions(ws: Path, current_draft: Path) -> Tuple[List[Dict], str]:
    """Load prior submissions for dupe comparison and describe the source."""
    tracker = find_submission_file(ws)
    if tracker and tracker.exists():
        text = tracker.read_text()
        subs = load_submission_entries_from_text(text)
        return subs, f"workspace ledger: {tracker}"

    subs = []
    staging_dir = ws / "submissions" / "staging"
    if staging_dir.exists():
        for draft_file in staging_dir.glob("*.md"):
            if draft_file.resolve() == current_draft.resolve():
                continue
            if any(draft_file.name.endswith(suffix) for suffix in SKIP_DRAFT_SUFFIXES):
                continue
            title = extract_title_from_draft(draft_file)
            if title:
                subs.append({
                    "title": title,
                    "status": "Draft",
                    "text": draft_file.read_text(),
                })
    if subs:
        return subs, f"fallback staging drafts: {staging_dir}"
    return subs, "no submission ledger or sibling staging drafts found"


def extract_title_from_draft(filepath: Path) -> Optional[str]:
    """Extract title from draft markdown file."""
    try:
        text = filepath.read_text()
        for line in text.splitlines()[:20]:
            if line.startswith("# "):
                return line.lstrip("# ").strip()
    except Exception:
        pass
    return None


def extract_features(text: str) -> Dict[str, Any]:
    """Extract structured features from submission text."""
    text_lower = text.lower()
    
    # Contracts mentioned
    contracts = set()
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', text):
        contracts.add(m.group(1))
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.(\w+)', text):
        contracts.add(m.group(1))
    
    # Functions mentioned
    functions = set()
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.(\w+)', text):
        functions.add(m.group(2))
    
    # Bug class
    bug_classes = []
    bug_keywords = {
        "reentrancy": ["reentrancy", "reentrant", "callback", "ghost-fill"],
        "oracle": ["oracle", "stale price", "price manipulation", "latestanswer"],
        "access_control": ["unauthenticated", "missing access control", "onlyowner", "auth", "permission"],
        "timestamp": ["timestamp", "block.timestamp", "block.number", "time-dependent"],
        "delegatecall": ["delegatecall", "delegate", "proxy hijack"],
        "erc4626": ["erc4626", "share price", "inflation attack", "donation"],
        "flash_loan": ["flash loan", "flashloan", "flash borrow"],
        "overflow": ["overflow", "underflow", "uint248", "panic"],
        "race_condition": ["race condition", "toctou", "state race"],
        "upgrade": ["upgrade", "initializer", "__gap", "storage collision"],
    }
    for bug_class, keywords in bug_keywords.items():
        if any(kw in text_lower for kw in keywords):
            bug_classes.append(bug_class)
    
    # Impact description (extract sentences with impact keywords)
    impact_sentences = []
    for sentence in re.split(r'[.!?]\s+', text):
        if any(kw in sentence.lower() for kw in ["impact", "loss", "theft", "drain", "exploit", "attacker", "fund", "value"]):
            impact_sentences.append(sentence.strip())
    impact_text = " ".join(impact_sentences[:3])
    
    # Code path keywords (how the bug is triggered)
    code_path = []
    for sentence in re.split(r'[.!?]\s+', text):
        if any(kw in sentence.lower() for kw in ["step", "sequence", "call", "function", "trigger", "invoke"]):
            code_path.append(sentence.strip())
    
    return {
        "contracts": contracts,
        "functions": functions,
        "bug_classes": bug_classes,
        "impact_text": impact_text,
        "code_path": code_path,
    }


def compute_similarity(draft: Dict, prior: Dict) -> Tuple[float, List[str]]:
    """Compute similarity score between draft and prior submission."""
    score = 0.0
    rationale = []
    
    # 1. Contract overlap (40% weight, max 40 points)
    draft_contracts = draft["contracts"]
    prior_contracts = prior["contracts"]
    if draft_contracts and prior_contracts:
        overlap = draft_contracts & prior_contracts
        union = draft_contracts | prior_contracts
        if union:
            contract_sim = len(overlap) / len(union)
            contract_score = contract_sim * 40
            score += contract_score
            if contract_sim > 0.5:
                rationale.append(f"High contract overlap: {', '.join(overlap)} ({contract_sim:.0%})")
            elif contract_sim > 0:
                rationale.append(f"Some contract overlap: {', '.join(overlap)} ({contract_sim:.0%})")
    
    # 2. Function overlap (extra penalty if same contract + same function)
    draft_funcs = draft["functions"]
    prior_funcs = prior["functions"]
    if draft_funcs and prior_funcs:
        func_overlap = draft_funcs & prior_funcs
        if func_overlap:
            # Same function on same contract = strong dupe signal
            score += 15
            rationale.append(f"Same functions mentioned: {', '.join(func_overlap)}")
    
    # 3. Bug class overlap (25% weight, max 25 points)
    draft_bugs = set(draft["bug_classes"])
    prior_bugs = set(prior["bug_classes"])
    if draft_bugs and prior_bugs:
        bug_overlap = draft_bugs & prior_bugs
        if bug_overlap:
            bug_score = (len(bug_overlap) / max(len(draft_bugs), len(prior_bugs))) * 25
            score += bug_score
            rationale.append(f"Same bug class: {', '.join(bug_overlap)}")
    
    # 4. Impact text similarity (20% weight)
    draft_impact = draft["impact_text"].lower().split()
    prior_impact = prior["impact_text"].lower().split()
    if draft_impact and prior_impact:
        # Simple word overlap
        draft_impact_set = set(w for w in draft_impact if len(w) > 4)
        prior_impact_set = set(w for w in prior_impact if len(w) > 4)
        if draft_impact_set and prior_impact_set:
            overlap = draft_impact_set & prior_impact_set
            union = draft_impact_set | prior_impact_set
            impact_sim = len(overlap) / len(union)
            impact_score = impact_sim * 20
            score += impact_score
            if impact_sim > 0.3:
                rationale.append(f"Similar impact description ({impact_sim:.0%} word overlap)")
    
    # 5. Code path distinctness (15% weight, but negative)
    # If code paths are explicitly different, reduce score
    draft_path = " ".join(draft["code_path"]).lower()
    prior_path = " ".join(prior["code_path"]).lower()
    if draft_path and prior_path:
        # Check for explicit distinction language
        distinction_keywords = ["different code path", "distinct vector", "variant", "different function", "not the same"]
        if any(kw in draft_path for kw in distinction_keywords):
            score -= 10
            rationale.append("Draft claims distinct vector (score reduced)")
    
    # Cap score at 100
    score = min(100, max(0, score))
    
    return score, rationale


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare one staging draft against the workspace submission ledger or sibling staging drafts."
    )
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("draft", help="Draft submission file (typically under submissions/staging/)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable risk output")
    parser.add_argument("--threshold-high", type=float, default=70, help="High risk threshold")
    parser.add_argument("--threshold-medium", type=float, default=30, help="Medium risk threshold")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    draft_path = Path(args.draft).expanduser().resolve()
    
    if not ws.exists():
        print(f"[variant] Workspace not found: {ws}")
        sys.exit(1)
    if not draft_path.exists():
        print(f"[variant] Draft not found: {draft_path}")
        sys.exit(1)

    emit_logs = not args.json

    def log(message: str) -> None:
        if emit_logs:
            print(message)

    # Load draft
    draft_text = draft_path.read_text()
    draft_features = extract_features(draft_text)
    
    # Load prior submissions
    subs, comparison_source = load_submissions(ws, draft_path)
    log(f"[variant] Comparison source: {comparison_source}")
    log(f"[variant] Comparing against {len(subs)} prior submission(s)")

    # Score against each prior submission
    results = []
    for sub in subs:
        sub_text = sub.get("text", "") or (sub.get("title", "") + " " + sub.get("status", ""))
        sub_features = extract_features(sub_text)
        score, rationale = compute_similarity(draft_features, sub_features)
        
        if score > 0:
            results.append({
                "submission": sub,
                "score": score,
                "rationale": rationale,
            })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)

    # Determine overall risk
    top_score = results[0]["score"] if results else 0
    if top_score >= args.threshold_high:
        risk_level = "HIGH"
        exit_code = 2
    elif top_score >= args.threshold_medium:
        risk_level = "MEDIUM"
        exit_code = 1
    else:
        risk_level = "LOW"
        exit_code = 0

    if args.json:
        output = {
            "draft": str(draft_path),
            "workspace": ws.name,
            "comparison_source": comparison_source,
            "risk_level": risk_level,
            "top_score": top_score,
            "matches": [
                {
                    "title": r["submission"].get("title", "")[:80],
                    "status": r["submission"].get("status", "?"),
                    "score": r["score"],
                    "rationale": r["rationale"],
                }
                for r in results[:5]
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"Dupe Risk Assessment: {risk_level} (top score: {top_score:.1f}/100)")
        print(f"{'='*70}")
        
        if results:
            print(f"\nTop matches:")
            for i, r in enumerate(results[:5], 1):
                sub = r["submission"]
                print(f"\n{i}. Score: {r['score']:.1f} — {sub.get('title', '')[:60]}")
                print(f"   Status: {sub.get('status', '?')}")
                for reason in r["rationale"]:
                    print(f"   → {reason}")
        else:
            print("\nNo significant overlap with prior submissions.")
            if comparison_source == "no submission ledger or sibling staging drafts found":
                print("Comparison source: none found — treat this LOW result as exploratory only.")
        
        print(f"\n{'='*70}")
        if risk_level == "HIGH":
            print("RECOMMENDATION: Do NOT submit — likely dupe or near-variant.")
            print("Add explicit distinction paragraph or find a different surface.")
        elif risk_level == "MEDIUM":
            print("RECOMMENDATION: Review carefully — possible same-class finding.")
            print("Add 'Distinction from prior findings' section before submitting.")
        else:
            print("RECOMMENDATION: Low dupe risk — proceed with pre-submit-check.")
        print(f"{'='*70}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
