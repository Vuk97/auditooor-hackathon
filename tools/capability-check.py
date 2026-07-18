#!/usr/bin/env python3
"""
capability-check.py -- Run verification_command for a capability and update verification_history.

Schema: auditooor.capability_check.v1

Usage:
  python3 tools/capability-check.py --capability CAP-make-hunt
  python3 tools/capability-check.py --all
  python3 tools/capability-check.py --category mcp-callable

Wrappers:
  make capability-check NAME=<id>
  make capability-check-all
"""

from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = REPO_ROOT / "reference" / "capability_inventory.jsonl"

NOW_ISO = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

MAX_HISTORY = 5
DEFAULT_TIMEOUT = 15  # seconds


def load_inventory() -> list[dict]:
    if not INVENTORY_PATH.exists():
        print(f"[capability-check] ERR inventory not found at {INVENTORY_PATH}")
        print("[capability-check] Run: python3 tools/capability-inventory-build.py --refresh")
        sys.exit(1)
    records = []
    with open(INVENTORY_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def save_inventory(records: list[dict]) -> None:
    with open(INVENTORY_PATH, "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def run_verification(cap: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run the capability's verification_command and return a verdict dict."""
    cmd = cap.get("verification_command")
    expected_pat = cap.get("expected_verification_output", "")

    if not cmd:
        return {
            "ran_at": NOW_ISO,
            "command": None,
            "exit_code": None,
            "stdout_snippet": "",
            "stdout_match": False,
            "verdict": "SKIP-NO-COMMAND",
        }

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = (result.stdout + result.stderr)[:500]
        exit_code = result.returncode

        # Check expected pattern
        match = False
        if expected_pat:
            match = bool(re.search(expected_pat, stdout, re.IGNORECASE))
        else:
            match = exit_code == 0

        verdict = "PASS" if match else "FAIL"

    except subprocess.TimeoutExpired:
        stdout = f"TIMEOUT after {timeout}s"
        exit_code = -1
        match = False
        verdict = "TIMEOUT"
    except Exception as e:
        stdout = str(e)[:200]
        exit_code = -2
        match = False
        verdict = "ERROR"

    return {
        "ran_at": NOW_ISO,
        "command": cmd[:200],
        "exit_code": exit_code,
        "stdout_snippet": stdout[:300],
        "stdout_match": match,
        "verdict": verdict,
    }


def check_one(cap: dict, timeout: int = DEFAULT_TIMEOUT, verbose: bool = True) -> dict:
    """Run verification for one capability, update its history, return result."""
    result = run_verification(cap, timeout=timeout)

    # Update last_verified_at
    cap["last_verified_at"] = NOW_ISO

    # Prepend to verification_history (keep last MAX_HISTORY)
    history = cap.get("verification_history", [])
    history.insert(0, result)
    cap["verification_history"] = history[:MAX_HISTORY]

    if verbose:
        status_str = result["verdict"]
        exit_str = f"exit={result['exit_code']}" if result.get("exit_code") is not None else "no-command"
        print(f"  [{status_str}] {cap['id']} ({exit_str})")
        if result["verdict"] not in ("PASS", "SKIP-NO-COMMAND"):
            snippet = result.get("stdout_snippet", "")[:150]
            print(f"         output: {snippet}")

    return result


def format_result(cap: dict, result: dict) -> dict:
    return {
        "capability_id": cap["id"],
        "name": cap["name"],
        "category": cap["category"],
        "status": cap["status"],
        "ran_at": result["ran_at"],
        "command": result.get("command"),
        "exit_code": result.get("exit_code"),
        "stdout_match": result.get("stdout_match"),
        "verdict": result["verdict"],
        "last_5_verdicts": [h["verdict"] for h in cap.get("verification_history", [])[:5]],
        "known_bugs_count": len(cap.get("known_bugs", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run capability verification checks")
    parser.add_argument("--capability", "-c", help="Specific capability ID to check")
    parser.add_argument("--all", "-a", action="store_true", help="Check all capabilities")
    parser.add_argument("--category", help="Check all capabilities in a category")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout per check in seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--no-save", action="store_true", help="Do not save updated history to inventory")
    args = parser.parse_args()

    if not args.capability and not args.all and not args.category:
        parser.print_help()
        return 2

    records = load_inventory()
    rec_by_id = {r["id"]: r for r in records}

    targets = []
    if args.capability:
        if args.capability not in rec_by_id:
            # Try partial match
            matches = [r for r in records if args.capability.lower() in r["id"].lower()]
            if not matches:
                print(f"[capability-check] ERR capability '{args.capability}' not found in inventory")
                print(f"[capability-check] Available IDs (first 10): {[r['id'] for r in records[:10]]}")
                return 1
            targets = matches[:1]
        else:
            targets = [rec_by_id[args.capability]]
    elif args.all:
        targets = records
    elif args.category:
        targets = [r for r in records if r.get("category") == args.category]
        if not targets:
            print(f"[capability-check] ERR no capabilities found in category '{args.category}'")
            print(f"[capability-check] Available categories: {sorted(set(r.get('category','') for r in records))}")
            return 1

    print(f"[capability-check] Checking {len(targets)} capability/capabilities...")
    results = []
    for cap in targets:
        result = check_one(cap, timeout=args.timeout, verbose=not args.json)
        results.append(format_result(cap, result))

    if not args.no_save:
        save_inventory(records)
        if not args.json:
            print(f"[capability-check] Updated verification_history in {INVENTORY_PATH}")

    # Summary
    pass_count = sum(1 for r in results if r["verdict"] == "PASS")
    fail_count = sum(1 for r in results if r["verdict"] == "FAIL")
    skip_count = sum(1 for r in results if "SKIP" in r["verdict"])
    other_count = len(results) - pass_count - fail_count - skip_count

    if args.json:
        print(json.dumps({
            "schema": "auditooor.capability_check.v1",
            "ran_at": NOW_ISO,
            "total": len(results),
            "pass": pass_count,
            "fail": fail_count,
            "skip": skip_count,
            "other": other_count,
            "results": results,
        }, indent=2))
    else:
        print(f"\n[capability-check] Summary: {pass_count} PASS / {fail_count} FAIL / {skip_count} SKIP / {other_count} OTHER out of {len(results)} total")
        if fail_count > 0:
            print("[capability-check] Failed capabilities:")
            for r in results:
                if r["verdict"] == "FAIL":
                    print(f"  - {r['capability_id']}: {r.get('command','')[:80]}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
