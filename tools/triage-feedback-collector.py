#!/usr/bin/env python3
"""
triage-feedback-collector.py

Maintain a structured database of triager feedback patterns and classify
drafts against them before submission.

Usage:
  python tools/triage-feedback-collector.py --check-draft <draft.md>
  python tools/triage-feedback-collector.py --add-pattern \
      --type rejection --id R8 --name "New Pattern" --trigger "keyword" \
      --severity-blocker
  python tools/triage-feedback-collector.py --list
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

PATTERNS_FILE = Path(__file__).parent.parent / "reference" / "triager_patterns.json"


def load_patterns() -> Dict:
    if PATTERNS_FILE.exists():
        with open(PATTERNS_FILE, "r") as f:
            return json.load(f)
    return {"rejections": [], "acceptances": [], "in_review_risks": [], "version": 1}


def save_patterns(patterns: Dict):
    PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PATTERNS_FILE, "w") as f:
        json.dump(patterns, f, indent=2)
        f.write("\n")


def parse_markdown_patterns() -> Dict:
    """Parse reference/triager_patterns.md into structured JSON."""
    md_file = Path(__file__).parent.parent / "reference" / "triager_patterns.md"
    if not md_file.exists():
        return load_patterns()

    patterns = {"rejections": [], "acceptances": [], "in_review_risks": [], "version": 1}
    current_section = None
    current_pattern = {}

    with open(md_file, "r") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith("### R") and " — " in line:
            if current_pattern and current_section:
                patterns[current_section].append(current_pattern)
            current_section = "rejections"
            current_pattern = {
                "id": line.split(" — ")[0].replace("### ", ""),
                "name": line.split(" — ")[1],
                "triggers": [],
                "triager_language": [],
                "pre_submit_guard": "",
                "severity": "warn",  # or "block"
            }
        elif line.startswith("### A") and " — " in line:
            if current_pattern and current_section:
                patterns[current_section].append(current_pattern)
            current_section = "acceptances"
            current_pattern = {
                "id": line.split(" — ")[0].replace("### ", ""),
                "name": line.split(" — ")[1],
            }
        elif line.startswith("### I") and " — " in line:
            if current_pattern and current_section:
                patterns[current_section].append(current_pattern)
            current_section = "in_review_risks"
            current_pattern = {
                "id": line.split(" — ")[0].replace("### ", ""),
                "name": line.split(" — ")[1],
            }
        elif line.startswith("**Pattern:**"):
            current_pattern["description"] = line.replace("**Pattern:**", "").strip()
        elif line.startswith("**Examples:**"):
            current_pattern["examples"] = []
        elif line.startswith("- ") and "examples" in current_pattern:
            current_pattern["examples"].append(line[2:])
        elif line.startswith("**Triager language:**"):
            langs = line.replace("**Triager language:**", "").strip().split("\"")
            current_pattern["triager_language"] = [
                cleaned
                for raw in langs
                for cleaned in [raw.strip(" .,")]
                if cleaned and cleaned not in {"or"}
            ]
        elif line.startswith("**Pre-submit guard:**"):
            current_pattern["pre_submit_guard"] = line.replace("**Pre-submit guard:**", "").strip()
        elif line.startswith("**Key:**") or line.startswith("**Key lesson:**"):
            current_pattern["key_lesson"] = line.replace("**Key:**", "").replace("**Key lesson:**", "").strip()
        elif line.startswith("**Mitigation:**"):
            current_pattern["mitigation"] = line.replace("**Mitigation:**", "").strip()

    if current_pattern and current_section:
        patterns[current_section].append(current_pattern)

    return patterns


def check_draft(draft_path: str, patterns: Dict) -> List[Dict]:
    """Check a draft against all rejection patterns."""
    with open(draft_path, "r") as f:
        text = f.read().lower()

    hits = []
    for pattern in patterns.get("rejections", []):
        score = 0
        matched_triggers = []

        # Check description keywords
        desc = pattern.get("description", "").lower()
        # Simple heuristic: split into sentences, check for keyword overlap
        keywords = re.findall(r'\b\w{4,}\b', desc)
        for kw in keywords:
            if kw in text and kw not in ("finding", "contract", "function", "address", "memory"):
                score += 1
                matched_triggers.append(kw)

        # Check explicit triggers
        for trigger in pattern.get("triggers", []):
            if trigger.lower() in text:
                score += 3
                matched_triggers.append(trigger)

        # Check triager language
        for lang in pattern.get("triager_language", []):
            if lang.lower() in text:
                score += 2
                matched_triggers.append(lang)

        if score >= 3:
            hits.append({
                "pattern_id": pattern["id"],
                "pattern_name": pattern["name"],
                "severity": pattern.get("severity", "warn"),
                "score": score,
                "matched": matched_triggers[:5],
                "guard": pattern.get("pre_submit_guard", ""),
            })

    return sorted(hits, key=lambda x: x["score"], reverse=True)


def main():
    parser = argparse.ArgumentParser(description="Triager feedback collector and draft classifier")
    parser.add_argument("--check-draft", help="Path to draft markdown file to classify")
    parser.add_argument("--add-pattern", action="store_true", help="Add a new pattern interactively")
    parser.add_argument("--type", choices=["rejection", "acceptance", "risk"], help="Pattern type")
    parser.add_argument("--id", help="Pattern ID (e.g., R8)")
    parser.add_argument("--name", help="Pattern name")
    parser.add_argument("--trigger", help="Trigger keyword/phrase")
    parser.add_argument("--severity-blocker", action="store_true", help="Mark as blocking")
    parser.add_argument("--list", action="store_true", help="List all patterns")
    parser.add_argument("--sync-from-md", action="store_true", help="Sync JSON from markdown")
    parser.add_argument("--format", choices=["json", "human"], default="human", help="Output format")

    args = parser.parse_args()

    if args.sync_from_md:
        patterns = parse_markdown_patterns()
        save_patterns(patterns)
        print(f"Synced {len(patterns['rejections'])} rejections, "
              f"{len(patterns['acceptances'])} acceptances, "
              f"{len(patterns['in_review_risks'])} risks from markdown")
        return

    patterns = load_patterns()

    if args.list:
        print("=== REJECTION PATTERNS ===")
        for p in patterns.get("rejections", []):
            sev = "BLOCK" if p.get("severity") == "block" else "WARN"
            print(f"  [{sev}] {p['id']}: {p['name']}")
        print("\n=== ACCEPTANCE PATTERNS ===")
        for p in patterns.get("acceptances", []):
            print(f"  [GOOD] {p['id']}: {p['name']}")
        return

    if args.check_draft:
        hits = check_draft(args.check_draft, patterns)
        if args.format == "json":
            print(json.dumps(hits, indent=2))
        else:
            if not hits:
                print("✅ No rejection patterns matched")
                sys.exit(0)
            max_sev = max((h["severity"] for h in hits), key=lambda s: {"warn": 0, "block": 1}.get(s, 0))
            prefix = "❌ BLOCK" if max_sev == "block" else "⚠️  WARN"
            print(f"{prefix}: Matched {len(hits)} triager pattern(s)")
            for h in hits:
                icon = "❌" if h["severity"] == "block" else "⚠️"
                print(f"  {icon} {h['pattern_id']} ({h['score']}pts): {h['pattern_name']}")
                print(f"     Matched: {', '.join(h['matched'])}")
                if h["guard"]:
                    print(f"     Guard: {h['guard']}")
            sys.exit(1 if max_sev == "block" else 0)

    if args.add_pattern:
        if not all([args.type, args.id, args.name]):
            print("--add-pattern requires --type, --id, --name")
            sys.exit(1)
        section = {"rejection": "rejections", "acceptance": "acceptances", "risk": "in_review_risks"}[args.type]
        new_pat = {
            "id": args.id,
            "name": args.name,
            "severity": "block" if args.severity_blocker else "warn",
            "triggers": [args.trigger] if args.trigger else [],
        }
        patterns[section].append(new_pat)
        save_patterns(patterns)
        print(f"Added {args.id} to {section}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
