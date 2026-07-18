#!/usr/bin/env python3
"""
Wave-7 ranker evaluation: measure precision@5 on filed Cantina/Immunefi submissions.
Reads vulnerability metadata from paste_ready/filed/*.md and scores against ranker predictions.
"""

import os
import sys
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Import ranker functions
sys.path.insert(0, os.path.dirname(__file__))
import ranker as ranker_module


def extract_filing_metadata(fpath: str) -> Optional[Dict]:
    """Extract filing ID, bug class, repo, function, file from a submission file."""
    fname = os.path.basename(fpath)

    # Guess filing_id from filename
    filing_match = re.search(r"(cantina-\d+|cantina-PENDING\d+|immunefi-\w+)", fname)
    if not filing_match:
        return None
    filing_id = filing_match.group(1)

    # Guess severity
    severity_match = re.search(r"(CRITICAL|HIGH|MEDIUM|LOW)\.md", fname)
    severity = severity_match.group(1) if severity_match else "UNKNOWN"

    # Read file
    try:
        with open(fpath, 'r') as f:
            content = f.read()
    except:
        return None

    # Extract vulnerable_file and vulnerable_function from ## Vulnerability section
    vuln_file = "UNKNOWN"
    vuln_func = "UNKNOWN"

    vuln_section = re.search(r"##\s*Vulnerab[a-z]*\s+(.*?)(?=##\s|\Z)", content, re.DOTALL | re.IGNORECASE)
    if vuln_section:
        vuln_text = vuln_section.group(1)
        # Look for file path patterns
        file_match = re.search(r"(?:File|path|contract):\s*[`\*]*([^\s\*`\n]+)", vuln_text, re.IGNORECASE)
        if file_match:
            vuln_file = file_match.group(1)
        # Look for function name
        func_match = re.search(r"(?:Function|method|function name):\s*[`\*]*([^\s\*`\n]+)", vuln_text, re.IGNORECASE)
        if func_match:
            vuln_func = func_match.group(1)

    # Extract attack class from title or bug class field
    attack_class = fname
    title_match = re.search(r"(dydx|spark)-([a-z\-]+)-(?:CRITICAL|HIGH|MEDIUM|LOW)", fname)
    if title_match:
        attack_class = title_match.group(2).replace("-", "_")

    # Infer repo from filename/path
    if "dydx" in fname.lower():
        repo = "dydxprotocol/v4-chain"
    elif "spark" in fname.lower():
        repo = "buildonspark/spark"
    else:
        repo = "UNKNOWN"

    return {
        "filing_id": filing_id,
        "target_repo": repo,
        "vulnerable_file_path": vuln_file,
        "vulnerable_function": vuln_func,
        "actual_attack_class": attack_class,
        "severity": severity,
    }


def eval_filing(metadata: Dict) -> Dict:
    """
    Score filing against ranker's heuristics.
    Return prediction accuracy (hit_at_5, confidence).
    """
    query = f"{metadata['vulnerable_function']} {metadata['vulnerable_file_path']}"

    try:
        # Load tags and weights
        tags = ranker_module.load_tags()
        weights = ranker_module.load_weights()
        families = ranker_module.load_sibling_families()

        # Score each tag using ranker's s1 heuristic
        scored_tags = []
        for tag in tags:
            try:
                s1_score = ranker_module.score_s1(tag, query)
                if s1_score > 0:
                    scored_tags.append((s1_score, tag.bug_class))
            except:
                pass

        # Sort by score and get top-5
        scored_tags.sort(key=lambda x: -x[0])
        predictions = [{"attack_class": bc, "confidence": float(score)}
                      for score, bc in scored_tags[:5]]

    except Exception as e:
        print(f"Error scoring {metadata['filing_id']}: {e}", file=sys.stderr)
        return {
            "filing_id": metadata["filing_id"],
            "error": str(e),
            "hit_at_5": False,
            "confidence": 0.0,
        }

    if not predictions:
        return {
            "filing_id": metadata["filing_id"],
            "error": "no predictions",
            "hit_at_5": False,
            "confidence": 0.0,
        }

    # Check if actual_attack_class appears in top-5
    predicted_classes = [p.get("attack_class", "") for p in predictions]
    hit = metadata["actual_attack_class"] in predicted_classes

    # Get confidence of the hit (if it exists)
    confidence = 0.0
    hit_idx = -1
    for i, p in enumerate(predictions):
        if p.get("attack_class", "") == metadata["actual_attack_class"]:
            confidence = float(p.get("confidence", 0.0))
            hit_idx = i
            break

    return {
        "filing_id": metadata["filing_id"],
        "actual_attack_class": metadata["actual_attack_class"],
        "predicted_top_5": predicted_classes,
        "hit_at_5": hit,
        "hit_position": hit_idx if hit else -1,
        "confidence": confidence,
        "severity": metadata["severity"],
    }


def main():
    # Locate filed submissions
    search_dirs = [
        Path("/Users/wolf/audits/dydx/submissions/paste_ready/filed"),
        Path("/Users/wolf/audits/spark/submissions/paste_ready"),
    ]

    filings = []
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for fpath in search_dir.glob("*.md"):
            if fpath.name.startswith("."):
                continue
            metadata = extract_filing_metadata(str(fpath))
            if metadata:
                filings.append(metadata)

    if not filings:
        print("No filed submissions found.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(filings)} filings.", file=sys.stderr)

    # Evaluate each filing
    results = []
    for metadata in sorted(filings, key=lambda x: x["filing_id"]):
        result = eval_filing(metadata)
        results.append(result)
        status = "HIT" if result.get("hit_at_5") else "MISS"
        print(f"{result['filing_id']:20} {status:4} conf={result.get('confidence', 0.0):.2f} "
              f"pos={result.get('hit_position', -1)}", file=sys.stderr)

    # Compute summary metrics
    hits = sum(1 for r in results if r.get("hit_at_5"))
    total = len(results)
    precision_at_5 = hits / total if total > 0 else 0.0

    confidences = [r["confidence"] for r in results if r.get("hit_at_5") and r["confidence"] > 0]
    mean_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    median_confidence = sorted(confidences)[len(confidences)//2] if confidences else 0.0

    # Build markdown output
    output = f"""# Ranker Evaluation Report

Generated: 2026-05-11  |  Total filings evaluated: {total}  |  Hits: {hits}

## Summary Metrics

| Metric | Value |
|--------|-------|
| Precision@5 | {precision_at_5:.2%} ({hits}/{total}) |
| Mean confidence (on hits) | {mean_confidence:.3f} |
| Median confidence (on hits) | {median_confidence:.3f} |
| Acceptance threshold (>= 0.625) | {"PASS" if precision_at_5 >= 0.625 else "FAIL"} |

## Per-Filing Results

| filing_id | severity | actual_attack_class | predicted_top_5 | hit_at_5 | hit_position | confidence |
|-----------|----------|---------------------|-----------------|----------|--------------|------------|
"""

    for result in sorted(results, key=lambda r: r["filing_id"]):
        predicted = ", ".join(result.get("predicted_top_5", [])[:3]) or "(none)"
        output += f"| {result['filing_id']:20} | {result.get('severity', 'N/A'):8} | "
        output += f"{result.get('actual_attack_class', 'N/A'):30} | {predicted:30} | "
        output += f"{'YES' if result.get('hit_at_5') else 'NO':8} | "
        output += f"{result.get('hit_position', -1):12} | {result.get('confidence', 0.0):.3f} |\n"

    output += f"""

## Verdict

Precision@5: {precision_at_5:.2%} (target: >= 62.5%)
Result: {"ACCEPT" if precision_at_5 >= 0.625 else "REJECT"}
"""

    # Write report
    output_file = "/Users/wolf/auditooor-worktrees/dlt-workflow-gaps-main/audit/ranker_eval_2026-05-11.md"
    with open(output_file, 'w') as f:
        f.write(output)

    print(output_file, file=sys.stderr)
    print(output)

    return 0 if precision_at_5 >= 0.625 else 1


if __name__ == "__main__":
    sys.exit(main())
