#!/usr/bin/env python3
"""
mcp-env-shell-export-audit.py - L33 rule enforcement auditor.

Reads ~/.claude.json to enumerate every mcpServers.<name>.env.<KEY>,
then greps ~/.zshrc / ~/.bashrc / ~/.profile for the corresponding
`export <KEY>=` line. Reports which keys are missing from shell-rc.

Rule 37: this miner emits no corpus records; audit-only tool.
L33 codification: 2026-05-23, iter2 Lane J Solodit-key pattern.

Usage:
  python3 tools/mcp-env-shell-export-audit.py [--json] [--rc <path>...]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple

# Default shell-rc files to search for export lines
DEFAULT_RC_FILES = [
    Path.home() / ".zshrc",
    Path.home() / ".bashrc",
    Path.home() / ".profile",
    Path.home() / ".bash_profile",
]

CLAUDE_JSON_PATH = Path.home() / ".claude.json"


def load_claude_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def enumerate_mcp_env_keys(claude_cfg: dict) -> List[Tuple[str, str]]:
    """Return list of (server_name, env_key) for all MCP env bindings."""
    results = []
    mcp_servers = claude_cfg.get("mcpServers", {})
    for server_name, server_cfg in mcp_servers.items():
        env_block = server_cfg.get("env", {})
        for key in env_block:
            results.append((server_name, key))
    return results


def grep_rc_for_export(key: str, rc_files: List[Path]) -> Dict[str, bool]:
    """For each rc_file, return True if `export <KEY>=` or `export <KEY> ` appears."""
    pattern = re.compile(rf'^\s*export\s+{re.escape(key)}\s*=', re.MULTILINE)
    found_in: Dict[str, bool] = {}
    for rc_path in rc_files:
        if not rc_path.exists():
            found_in[str(rc_path)] = False
            continue
        try:
            content = rc_path.read_text(errors="replace")
        except OSError:
            found_in[str(rc_path)] = False
            continue
        found_in[str(rc_path)] = bool(pattern.search(content))
    return found_in


def audit(rc_files: List[Path] = None) -> dict:
    if rc_files is None:
        rc_files = DEFAULT_RC_FILES

    claude_cfg = load_claude_json(CLAUDE_JSON_PATH)
    bindings = enumerate_mcp_env_keys(claude_cfg)

    missing: List[Dict] = []
    present: List[Dict] = []

    for server_name, key in bindings:
        found_in = grep_rc_for_export(key, rc_files)
        any_found = any(found_in.values())
        entry = {
            "server": server_name,
            "env_key": key,
            "found_in_shell_rc": any_found,
            "rc_search_results": {str(p): v for p, v in found_in.items()},
        }
        if any_found:
            present.append(entry)
        else:
            missing.append(entry)

    return {
        "claude_json_path": str(CLAUDE_JSON_PATH),
        "rc_files_checked": [str(p) for p in rc_files],
        "total_mcp_env_keys": len(bindings),
        "present_in_shell_rc": present,
        "missing_from_shell_rc": missing,
        "verdict": "pass" if not missing else "fail-missing-shell-rc-exports",
    }


def main():
    parser = argparse.ArgumentParser(description="L33 MCP env shell-rc export auditor")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--rc", nargs="+", metavar="PATH",
        help="Override default rc file list (absolute paths)"
    )
    args = parser.parse_args()

    rc_files = [Path(p) for p in args.rc] if args.rc else None
    result = audit(rc_files)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["verdict"] == "pass" else 1)

    # Human-readable output
    print(f"L33 MCP env shell-rc audit")
    print(f"  claude.json : {result['claude_json_path']}")
    print(f"  RC files    : {', '.join(result['rc_files_checked'])}")
    print(f"  Total MCP env keys: {result['total_mcp_env_keys']}")
    print()

    if result["present_in_shell_rc"]:
        print(f"[PASS] {len(result['present_in_shell_rc'])} key(s) already exported in shell-rc:")
        for e in result["present_in_shell_rc"]:
            hits = [p for p, v in e["rc_search_results"].items() if v]
            print(f"  {e['server']}.{e['env_key']} -> found in {hits[0]}")
    print()

    if result["missing_from_shell_rc"]:
        print(f"[FAIL] {len(result['missing_from_shell_rc'])} key(s) missing from shell-rc (L33 violation):")
        for e in result["missing_from_shell_rc"]:
            print(f"  {e['server']}.{e['env_key']}")
            print(f"    Fix: add `export {e['env_key']}=<value>` to ~/.zshrc")
        sys.exit(1)
    else:
        print("[PASS] All MCP env keys are also exported in shell-rc.")
        sys.exit(0)


if __name__ == "__main__":
    main()
