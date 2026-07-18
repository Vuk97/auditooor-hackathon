#!/usr/bin/env python3
"""
forge-test-runner.py — Intelligent Foundry test runner

Auto-detects the correct solc version for a test file, handles multi-version
compilation, and runs forge test with structured output. Integrates with
solc-version-manager.py for version resolution.

Usage:
    forge-test-runner.py <test-file.t.sol> [--workspace <ws>]
    forge-test-runner.py ~/audits/polymarket/poc-tests/PoC_A-REENT_CTFExchange.t.sol
    forge-test-runner.py <test-file> --verbose

Exit codes:
    0 — all tests passed
    1 — compilation or test failure
    2 — forge not found or solc unavailable
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent
FORGE_RESOLVE = AUDITOOOR_DIR / "tools" / "lib" / "forge-resolve.sh"


def resolve_forge() -> Optional[str]:
    """Resolve forge binary using the canonical resolver."""
    if FORGE_RESOLVE.exists():
        result = subprocess.run(
            ["bash", "-c", f'source "{FORGE_RESOLVE}" && echo "$FORGE_BIN"'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            if path and os.path.exists(path):
                return path
    # Fallback
    for candidate in [os.path.expanduser("~/.foundry/bin/forge"), "forge"]:
        if subprocess.run(["which", candidate], capture_output=True).returncode == 0:
            return candidate
    return None


def extract_pragma_from_test(filepath: Path) -> Optional[str]:
    """Extract pragma from test file or its imports."""
    try:
        text = filepath.read_text()
    except Exception:
        return None
    
    # Look for pragma in test file
    m = re.search(r'pragma\s+solidity\s+([^;]+);', text)
    if m:
        return m.group(1).strip()
    
    # Look for imports and check their pragma
    for imp in re.finditer(r'import\s+["\']([^"\']+)["\'];', text):
        imp_path = imp.group(1)
        # Try to resolve relative to test file
        candidate = filepath.parent / imp_path
        if not candidate.exists():
            # Try workspace src/
            candidate = filepath.parent.parent / "src" / imp_path
        if candidate.exists():
            pragma = extract_pragma_from_test(candidate)
            if pragma:
                return pragma
    
    return None


def find_forge_project_root(test_file: Path) -> Optional[Path]:
    """Walk up from test file to find foundry.toml."""
    current = test_file.parent
    while current != current.parent:
        if (current / "foundry.toml").exists():
            return current
        # Also check src/ sibling (common layout)
        for sibling in ["src", "src-v2", "contracts"]:
            if (current / sibling / "foundry.toml").exists():
                return current / sibling
        current = current.parent
    return None


def get_test_contract_name(filepath: Path) -> str:
    """Extract contract name from test file."""
    text = filepath.read_text()
    m = re.search(r'contract\s+([A-Za-z_][A-Za-z0-9_]*)', text)
    if m:
        return m.group(1)
    return filepath.stem


def run_forge_test(
    forge_bin: str,
    project_dir: Path,
    test_file: Path,
    contract_name: str,
    verbose: bool = False,
) -> Tuple[int, str, str]:
    """Run forge test and return (rc, stdout, stderr)."""
    cmd = [
        forge_bin,
        "test",
        "--match-path", f"*{test_file.name}*",
        "--match-contract", contract_name,
    ]
    if verbose:
        cmd.append("-vvv")
    
    env = os.environ.copy()
    # Ensure forge uses the right solc if we can determine it
    pragma = extract_pragma_from_test(test_file)
    if pragma:
        # Try to set solc version via env or foundry config
        # For now, rely on auto_detect_solc in foundry.toml
        pass
    
    result = subprocess.run(
        cmd,
        cwd=project_dir,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    return result.returncode, result.stdout, result.stderr


def parse_test_results(stdout: str) -> Dict[str, Any]:
    """Parse forge test output into structured results."""
    results = {
        "passed": 0,
        "failed": 0,
        "tests": [],
        "gas": {},
        "raw": stdout,
    }
    
    # Parse test results
    for line in stdout.splitlines():
        # Pattern: [PASS] testName() (gas: 12345)
        pass_match = re.search(r'\[PASS\]\s+(\S+)\s*\(gas:\s*(\d+)\)', line)
        if pass_match:
            results["passed"] += 1
            results["tests"].append({
                "name": pass_match.group(1),
                "status": "PASS",
                "gas": int(pass_match.group(2)),
            })
            continue
        
        # Pattern: [FAIL] testName()
        fail_match = re.search(r'\[FAIL\]\s+(\S+)', line)
        if fail_match:
            results["failed"] += 1
            results["tests"].append({
                "name": fail_match.group(1),
                "status": "FAIL",
            })
            continue
        
        # Pattern: Test result: ok. 3 passed; 0 failed; 0 skipped
        summary = re.search(r'Test result:\s+(\w+)\.\s+(\d+)\s+passed;\s+(\d+)\s+failed', line)
        if summary:
            results["passed"] = int(summary.group(2))
            results["failed"] = int(summary.group(3))
    
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Intelligent Foundry test runner")
    parser.add_argument("test_file", help="Path to .t.sol test file")
    parser.add_argument("--workspace", help="Workspace directory (auto-detected if not given)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose forge output (-vvv)")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("--no-build", action="store_true", help="Skip compilation, run tests only")
    args = parser.parse_args()

    test_file = Path(args.test_file).expanduser().resolve()
    if not test_file.exists():
        print(f"[forge] Test file not found: {test_file}")
        sys.exit(1)

    # Resolve forge
    forge_bin = resolve_forge()
    if not forge_bin:
        print("[forge] forge not found. Install Foundry or set FORGE_BIN.")
        sys.exit(2)

    # Find project root
    project_dir = find_forge_project_root(test_file)
    if not project_dir:
        # Fallback: use workspace or test file parent
        if args.workspace:
            project_dir = Path(args.workspace).expanduser().resolve()
        else:
            project_dir = test_file.parent
        print(f"[forge] Warning: no foundry.toml found, using {project_dir}")
    
    print(f"[forge] Project: {project_dir}")
    print(f"[forge] Test: {test_file.name}")
    print(f"[forge] Forge: {forge_bin}")
    
    # Detect solc version
    pragma = extract_pragma_from_test(test_file)
    if pragma:
        print(f"[forge] Pragma: {pragma}")
    
    # Get contract name
    contract_name = get_test_contract_name(test_file)
    print(f"[forge] Contract: {contract_name}")
    
    # Run tests
    print(f"[forge] Running tests ...")
    rc, stdout, stderr = run_forge_test(
        forge_bin, project_dir, test_file, contract_name, args.verbose
    )
    
    # Parse results
    results = parse_test_results(stdout)
    results["returncode"] = rc
    results["stderr"] = stderr
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + stdout)
        if stderr:
            print("STDERR:", stderr)
        
        print(f"\n[forge] Results: {results['passed']} passed, {results['failed']} failed")
        if rc == 0 and results['passed'] > 0:
            print("[forge] ✅ All tests passed")
        elif rc == 0:
            print("[forge] ⚠️  No tests matched — check contract name")
        else:
            print("[forge] ❌ Tests failed or compilation error")
    
    sys.exit(0 if rc == 0 and results['passed'] > 0 else 1)


if __name__ == "__main__":
    main()
