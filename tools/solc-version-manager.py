#!/usr/bin/env python3
"""
solc-version-manager.py — Multi-solc version workspace manager

Scans a workspace for all pragma statements, identifies required solc versions,
auto-installs missing ones via solc-select, and generates a foundry.toml
configuration that handles multi-version compilation.

Usage:
    solc-version-manager.py <workspace> [--install] [--write-toml]
    solc-version-manager.py ~/audits/<project> --install --write-toml
    solc-version-manager.py ~/audits/<project> --check              # just report

Exit codes:
    0 — all required versions available
    1 — missing versions (use --install to fix)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple


def find_sol_files(ws: Path) -> List[Path]:
    """Find all .sol files under workspace, excluding lib/test/out."""
    sol_files = []
    skip_dirs = {"lib", "test", "out", "node_modules", "cache", "artifacts", "agent_outputs"}
    for root, dirs, files in os.walk(ws):
        # Skip directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f.endswith(".sol"):
                sol_files.append(Path(root) / f)
    return sol_files


def extract_pragmas(filepath: Path) -> List[str]:
    """Extract pragma solidity statements from a file."""
    try:
        text = filepath.read_text()
    except Exception:
        return []
    pragmas = []
    for line in text.splitlines():
        m = re.search(r'pragma\s+solidity\s+([^;]+);', line)
        if m:
            pragmas.append(m.group(1).strip())
    return pragmas


def parse_version_range(pragma: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a pragma string into min/max version.
    
    Examples:
        ^0.8.0      -> (0.8.0, None)
        >=0.8.0     -> (0.8.0, None)
        >=0.8.0 <0.9.0 -> (0.8.0, 0.9.0)
        0.8.19      -> (0.8.19, 0.8.19)
        ~0.8.0      -> (0.8.0, None)
    """
    pragma = pragma.strip()
    
    # Exact version
    exact = re.match(r'^(\d+\.\d+\.\d+)$', pragma)
    if exact:
        return exact.group(1), exact.group(1)
    
    # Caret ^x.y.z
    caret = re.match(r'\^(\d+\.\d+\.\d+)', pragma)
    if caret:
        return caret.group(1), None
    
    # Tilde ~x.y.z
    tilde = re.match(r'~(\d+\.\d+\.\d+)', pragma)
    if tilde:
        return tilde.group(1), None
    
    # Range >=x.y.z <a.b.c
    range_match = re.match(r'>=(\d+\.\d+\.\d+)\s*<(\d+\.\d+\.\d+)', pragma)
    if range_match:
        return range_match.group(1), range_match.group(2)
    
    # Just >=x.y.z
    gte = re.match(r'>=(\d+\.\d+\.\d+)', pragma)
    if gte:
        return gte.group(1), None
    
    # Just <x.y.z
    lt = re.match(r'<(\d+\.\d+\.\d+)', pragma)
    if lt:
        return None, lt.group(1)
    
    return None, None


def get_installed_solc_versions() -> Set[str]:
    """Get list of installed solc versions via solc-select."""
    try:
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=10
        )
        versions = set()
        for line in result.stdout.splitlines():
            # Lines like "0.8.19 (current)" or "0.8.15"
            m = re.match(r'(\d+\.\d+\.\d+)', line.strip())
            if m:
                versions.add(m.group(1))
        return versions
    except Exception:
        return set()


def install_solc_version(version: str) -> bool:
    """Install a solc version via solc-select."""
    print(f"[solc] Installing solc {version} ...")
    try:
        result = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            print(f"[solc] Installed {version}")
            return True
        else:
            print(f"[solc] Failed to install {version}: {result.stderr}")
            return False
    except Exception as e:
        print(f"[solc] Error installing {version}: {e}")
        return False


def find_best_matching_version(required: str, installed: Set[str]) -> Optional[str]:
    """Find the best installed version matching a requirement."""
    req_parts = required.split('.')
    if len(req_parts) < 2:
        return None
    
    candidates = []
    for v in installed:
        v_parts = v.split('.')
        # Major match
        if v_parts[0] == req_parts[0]:
            # For ^0.8.0, any 0.8.x is fine
            if len(req_parts) >= 2 and v_parts[1] == req_parts[1]:
                candidates.append(v)
    
    if candidates:
        return max(candidates, key=lambda x: [int(p) for p in x.split('.')])
    return None


def scan_workspace(ws: Path) -> Tuple[Set[str], Set[str], dict]:
    """Scan workspace and return required versions, pragmas, and per-file info."""
    sol_files = find_sol_files(ws)
    all_pragmas = set()
    required_versions = set()
    per_file = {}
    
    for f in sol_files:
        pragmas = extract_pragmas(f)
        if pragmas:
            per_file[str(f.relative_to(ws))] = pragmas
            all_pragmas.update(pragmas)
            for p in pragmas:
                min_v, max_v = parse_version_range(p)
                if min_v:
                    required_versions.add(min_v)
    
    return required_versions, all_pragmas, per_file


def generate_foundry_profiles(required: Set[str]) -> str:
    """Generate foundry.toml profile section for multi-solc."""
    lines = ["# Auto-generated by solc-version-manager.py"]
    lines.append("[profile.default]")
    
    # Pick the most common major version as default
    major_counts = {}
    for v in required:
        major = '.'.join(v.split('.')[:2])
        major_counts[major] = major_counts.get(major, 0) + 1
    
    default_major = max(major_counts, key=major_counts.get) if major_counts else "0.8"
    default_versions = [v for v in required if v.startswith(default_major)]
    default_version = max(default_versions, key=lambda x: [int(p) for p in x.split('.')]) if default_versions else "0.8.19"
    
    lines.append(f'solc_version = "{default_version}"')
    lines.append('auto_detect_solc = true')
    lines.append("")
    
    # Create profiles for other major versions
    for major in sorted(major_counts.keys()):
        if major == default_major:
            continue
        versions = [v for v in required if v.startswith(major)]
        version = max(versions, key=lambda x: [int(p) for p in x.split('.')]) if versions else f"{major}.0"
        lines.append(f'[profile.solc{major.replace(".", "")}]')
        lines.append(f'solc_version = "{version}"')
        lines.append("")
    
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-solc version workspace manager")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--install", action="store_true", help="Install missing solc versions")
    parser.add_argument("--write-toml", action="store_true", help="Write foundry.toml profiles")
    parser.add_argument("--check", action="store_true", help="Just report status, no changes")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[solc] Workspace not found: {ws}")
        sys.exit(1)

    print(f"[solc] Scanning {ws} for Solidity files ...")
    required, all_pragmas, per_file = scan_workspace(ws)
    
    if not required:
        print("[solc] No pragma statements found")
        sys.exit(0)
    
    print(f"[solc] Found {len(required)} required version(s): {', '.join(sorted(required))}")
    
    installed = get_installed_solc_versions()
    print(f"[solc] Installed versions: {', '.join(sorted(installed)) if installed else 'none'}")
    
    missing = required - installed
    # Also check for compatible versions (e.g., ^0.8.0 works with any 0.8.x)
    truly_missing = set()
    for v in missing:
        match = find_best_matching_version(v, installed)
        if not match:
            truly_missing.add(v)
    
    if truly_missing:
        print(f"[solc] Missing versions: {', '.join(sorted(truly_missing))}")
        if args.install:
            for v in sorted(truly_missing):
                install_solc_version(v)
            # Re-check
            installed = get_installed_solc_versions()
            still_missing = truly_missing - installed
            if still_missing:
                print(f"[solc] Still missing after install: {', '.join(sorted(still_missing))}")
                sys.exit(1)
        else:
            print("[solc] Run with --install to auto-install missing versions")
            sys.exit(1)
    else:
        print("[solc] All required versions available")
    
    # Per-file version mapping
    file_versions = {}
    for fpath, pragmas in per_file.items():
        for p in pragmas:
            min_v, _ = parse_version_range(p)
            if min_v:
                match = find_best_matching_version(min_v, installed)
                if match:
                    file_versions[fpath] = match
                    break
    
    if args.write_toml:
        toml_text = generate_foundry_profiles(required)
        toml_path = ws / "foundry.toml.auto"
        toml_path.write_text(toml_text)
        print(f"[solc] Written multi-version config to {toml_path}")
        print(f"[solc] Copy to foundry.toml or use: cp {toml_path} {ws}/foundry.toml")
    
    if args.json:
        output = {
            "workspace": str(ws),
            "required_versions": sorted(required),
            "installed_versions": sorted(installed),
            "missing_versions": sorted(truly_missing),
            "file_version_map": file_versions,
            "pragmas": sorted(all_pragmas),
        }
        print(json.dumps(output, indent=2))
    else:
        # Show version distribution
        print("\n[solc] Version distribution:")
        major_counts = {}
        for v in required:
            major = '.'.join(v.split('.')[:2])
            major_counts[major] = major_counts.get(major, 0) + 1
        for major, count in sorted(major_counts.items()):
            print(f"  {major}.x: {count} file(s)")

    print("\n[solc] Done.")


if __name__ == "__main__":
    main()
