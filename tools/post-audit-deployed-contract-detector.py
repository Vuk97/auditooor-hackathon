#!/usr/bin/env python3
"""
post-audit-deployed-contract-detector.py — CAP-MORPHO-C

Checks each contract listed in a workspace SCOPE.md against its local repo
clone + audit-pin SHA.  Flags contracts that are deployed on-chain but not
present in src/ at the cited audit pin (POST-AUDIT-DEPLOYED).

Usage:
    python3 tools/post-audit-deployed-contract-detector.py --workspace <ws>
            [--scope-md <path>]
            [--repos-dir <path>]   # default: <ws>/src
            [--output <path>]      # default: <ws>/.auditooor/scope_pin_audit.json
            [--json]               # print JSON to stdout
            [--quiet]              # suppress non-verdict lines

Exit codes:
    0  all contracts IN-SCOPE-AT-PIN or needs-clarification
    1  at least one POST-AUDIT-DEPLOYED or PIN-UNRESOLVABLE contract found
    2  usage error or SCOPE.md not found
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
VERDICT_IN_SCOPE = "IN-SCOPE-AT-PIN"
VERDICT_POST_AUDIT = "POST-AUDIT-DEPLOYED"
VERDICT_PIN_UNRESOLVABLE = "PIN-UNRESOLVABLE"
VERDICT_NEEDS_CLARIFICATION = "NEEDS-OPERATOR-CLARIFICATION"
VERDICT_NO_LOCAL_REPO = "NO-LOCAL-REPO"

# ---------------------------------------------------------------------------
# SCOPE.md parser
# ---------------------------------------------------------------------------

_TABLE_ROW = re.compile(
    r"^\|\s*"
    r"(?P<name>[^|]+?)\s*\|"  # Contract name (may have bold/star)
    r"\s*(?P<address>[^|]*?)\s*\|"  # Address (may be empty)
    r"\s*(?P<repo>[^|]*?)\s*\|"  # Repo URL/path
    r"\s*(?P<pin>[^|`]*?)`(?P<sha>[0-9a-f]{7,64})`[^|]*\|",  # Pinned commit
    re.IGNORECASE,
)

_BARE_STAR = re.compile(r"[★*]")
_MARKDOWN_BOLD = re.compile(r"\*\*([^*]+)\*\*")

# Group-pin header: "All pinned to commit `<sha>` on github.com/org/repo"
_GROUP_PIN_HEADER = re.compile(
    r"all\s+pinned\s+to\s+commit\s+`([0-9a-f]{7,64})`\s+on\s+(github\.com/[^\s:,]+)",
    re.IGNORECASE,
)
# Group-pin list item: "- ContractName (0x...)"
_GROUP_PIN_ITEM = re.compile(
    r"^[-*]\s+"
    r"(?P<name>[A-Za-z0-9_.]+)"          # contract name (CamelCase identifier)
    r"(?:\s+\((?P<address>[^)]*)\))?"    # optional (address)
)


def _clean_name(raw: str) -> str:
    s = _MARKDOWN_BOLD.sub(r"\1", raw)
    s = _BARE_STAR.sub("", s)
    return s.strip()


def _repo_name_from_url(repo: str) -> str:
    """Extract 'vault-v2-adapter-registries' from 'github.com/morpho-org/vault-v2-adapter-registries'."""
    repo = repo.strip().rstrip("/")
    return repo.split("/")[-1] if "/" in repo else repo


def parse_scope_md(scope_md_path: Path) -> list[dict[str, str]]:
    """Return list of {name, address, repo, pin, repo_name} from SCOPE.md tables.

    Handles two formats:
      1. Standard table row with inline repo + pin columns.
      2. Group-pin prose: "All pinned to commit `sha` on github.com/org/repo:"
         followed by list items "- ContractName (address)".
    """
    contracts: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # State for group-pin parsing
    group_pin: str | None = None
    group_repo: str | None = None

    with scope_md_path.open() as fh:
        for line in fh:
            # -- Check for group-pin header --
            gm = _GROUP_PIN_HEADER.search(line)
            if gm:
                group_pin = gm.group(1).strip()
                group_repo = gm.group(2).strip()
                continue

            # -- Check for group-pin list item --
            if group_pin and group_repo and line.startswith(("-", "*")):
                im = _GROUP_PIN_ITEM.match(line.strip())
                if im:
                    name = im.group("name").strip()
                    address = (im.group("address") or "").strip()
                    key = (name, group_pin)
                    if key not in seen:
                        seen.add(key)
                        contracts.append(
                            {
                                "name": name,
                                "address": address,
                                "repo": group_repo,
                                "pin": group_pin,
                                "repo_name": _repo_name_from_url(group_repo),
                            }
                        )
                    continue

            # -- Standard table row --
            m = _TABLE_ROW.match(line)
            if not m:
                # A blank or non-list line clears group-pin context
                if group_pin and line.strip() and not line.startswith(("-", "*")):
                    group_pin = None
                    group_repo = None
                continue

            name = _clean_name(m.group("name"))
            address = m.group("address").strip()
            repo = m.group("repo").strip()
            pin = m.group("sha").strip()
            # de-duplicate (same pin can appear in group rows)
            key = (name, pin)
            if key in seen:
                continue
            seen.add(key)
            contracts.append(
                {
                    "name": name,
                    "address": address,
                    "repo": repo,
                    "pin": pin,
                    "repo_name": _repo_name_from_url(repo),
                }
            )
    return contracts


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 1, "", "git not found"


def pin_resolvable(repo_dir: Path, sha: str) -> bool:
    rc, out, _ = _run(["git", "cat-file", "-t", sha], cwd=repo_dir)
    return rc == 0 and out == "commit"


def files_at_pin(repo_dir: Path, sha: str) -> list[str]:
    """Return list of paths tracked at the given commit."""
    rc, out, _ = _run(["git", "ls-tree", "-r", "--name-only", sha], cwd=repo_dir)
    if rc != 0:
        return []
    return [l for l in out.splitlines() if l]


def _contract_name_to_filename(name: str) -> str:
    """ERC20WrapperAdapter -> ERC20WrapperAdapter.sol  (strip trailing star/space)."""
    clean = re.sub(r"[★*\s]", "", name)
    return clean + ".sol"


def _contract_name_variants(name: str) -> list[str]:
    """Return list of candidate .sol filenames for a contract name.

    Handles cases like:
      'Morpho Blue' -> ['MorphoBlue.sol', 'Morpho.sol']
      'ERC20WrapperAdapter' -> ['ERC20WrapperAdapter.sol']
      'Adaptive Curve IRM' -> ['AdaptiveCurveIRM.sol', 'AdaptiveCurve.sol']
    """
    # Primary: strip all spaces/special chars (e.g. MorphoBlue)
    primary = re.sub(r"[★*\s]", "", name)
    variants: list[str] = [primary + ".sol"]

    # Secondary: first word only (e.g. Morpho for "Morpho Blue")
    words = name.split()
    if len(words) > 1:
        first_word = re.sub(r"[★*]", "", words[0]).strip()
        if first_word and first_word != primary:
            variants.append(first_word + ".sol")

    return variants


# ---------------------------------------------------------------------------
# Core checker
# ---------------------------------------------------------------------------


def check_contract(
    contract: dict[str, str],
    repos_dir: Path,
) -> dict[str, Any]:
    name = contract["name"]
    pin = contract["pin"]
    repo_name = contract["repo_name"]
    repo_dir = repos_dir / repo_name

    result: dict[str, Any] = {
        "name": name,
        "pin": pin,
        "address": contract["address"],
        "repo": contract["repo"],
        "repo_name": repo_name,
        "local_repo": str(repo_dir),
        "pin_resolvable": False,
        "contract_at_pin": False,
        "matched_path": None,
        "verdict": VERDICT_NEEDS_CLARIFICATION,
        "note": "",
    }

    # 1. Check local repo exists
    if not repo_dir.exists():
        result["verdict"] = VERDICT_NO_LOCAL_REPO
        result["note"] = f"Local repo not found at {repo_dir}"
        return result

    # 2. Check pin resolvability
    resolvable = pin_resolvable(repo_dir, pin)
    result["pin_resolvable"] = resolvable

    if not resolvable:
        result["verdict"] = VERDICT_PIN_UNRESOLVABLE
        result["note"] = (
            f"SHA {pin} does not resolve in {repo_dir}. "
            "Run: git fetch --unshallow origin in the repo."
        )
        return result

    # 3. Enumerate files at pin
    tracked = files_at_pin(repo_dir, pin)
    candidate_names = _contract_name_variants(name)

    # Search in src/ only (not test/, lib/, etc.)
    src_files = [f for f in tracked if f.startswith("src/")]
    matched: list[str] = []

    for candidate in candidate_names:
        exact = [f for f in src_files if Path(f).name == candidate]
        if exact:
            matched = exact
            break
        ci = [f for f in src_files if Path(f).name.lower() == candidate.lower()]
        if ci:
            matched = ci
            break

    result["contract_at_pin"] = bool(matched)
    result["matched_path"] = matched[0] if matched else None

    if matched:
        result["verdict"] = VERDICT_IN_SCOPE
        result["note"] = f"Found at {matched[0]}"
    else:
        # Contract is listed in SCOPE.md but not in src/ at the audit pin
        result["verdict"] = VERDICT_POST_AUDIT
        tried = ", ".join(f"'{c}'" for c in candidate_names)
        result["note"] = (
            f"Tried {tried} - not found in src/ at pin {pin}. "
            f"Checked {len(src_files)} src/ file(s). "
            "Contract may have been deployed after the audit pin."
        )

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect POST-AUDIT-DEPLOYED contracts in a workspace SCOPE.md",
    )
    parser.add_argument("--workspace", "-w", required=True, help="Audit workspace root")
    parser.add_argument("--scope-md", help="Path to SCOPE.md (default: <workspace>/SCOPE.md)")
    parser.add_argument(
        "--repos-dir",
        help="Directory containing cloned repos (default: <workspace>/src)",
    )
    parser.add_argument(
        "--output",
        help="Output JSON path (default: <workspace>/.auditooor/scope_pin_audit.json)",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--quiet", action="store_true", help="Suppress info lines")
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"ERROR: workspace '{ws}' does not exist", file=sys.stderr)
        return 2

    scope_md = Path(args.scope_md) if args.scope_md else ws / "SCOPE.md"
    if not scope_md.exists():
        print(f"ERROR: SCOPE.md not found at '{scope_md}'", file=sys.stderr)
        return 2

    repos_dir = Path(args.repos_dir).expanduser().resolve() if args.repos_dir else ws / "src"

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else ws / ".auditooor" / "scope_pin_audit.json"
    )

    # Parse SCOPE.md
    contracts = parse_scope_md(scope_md)
    if not args.quiet:
        print(f"[post-audit-detector] Parsed {len(contracts)} pinned contract(s) from {scope_md}")

    # Check each contract
    results = []
    post_audit: list[str] = []
    pin_unresolvable: list[str] = []

    for c in contracts:
        r = check_contract(c, repos_dir)
        results.append(r)
        if not args.quiet:
            icon = {
                VERDICT_IN_SCOPE: "OK ",
                VERDICT_POST_AUDIT: "!!POST-AUDIT-DEPLOYED",
                VERDICT_PIN_UNRESOLVABLE: "??PIN-UNRESOLVABLE",
                VERDICT_NO_LOCAL_REPO: "-- NO-LOCAL-REPO",
                VERDICT_NEEDS_CLARIFICATION: "?? NEEDS-CLARIFICATION",
            }.get(r["verdict"], "?? " + r["verdict"])
            print(f"  [{icon}] {r['name']} @ {r['pin'][:12]}  — {r['note']}")

        if r["verdict"] == VERDICT_POST_AUDIT:
            post_audit.append(r["name"])
        elif r["verdict"] == VERDICT_PIN_UNRESOLVABLE:
            pin_unresolvable.append(r["name"])

    # Build summary
    summary = {
        "workspace": str(ws),
        "scope_md": str(scope_md),
        "total": len(results),
        "in_scope_at_pin": sum(1 for r in results if r["verdict"] == VERDICT_IN_SCOPE),
        "post_audit_deployed": len(post_audit),
        "pin_unresolvable": len(pin_unresolvable),
        "no_local_repo": sum(1 for r in results if r["verdict"] == VERDICT_NO_LOCAL_REPO),
        "needs_clarification": sum(
            1 for r in results if r["verdict"] == VERDICT_NEEDS_CLARIFICATION
        ),
        "post_audit_names": post_audit,
        "pin_unresolvable_names": pin_unresolvable,
        "contracts": results,
    }

    # Write JSON sidecar
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    if not args.quiet:
        print(f"[post-audit-detector] Sidecar written: {output_path}")
        if post_audit:
            print(
                f"[post-audit-detector] WARNING: {len(post_audit)} POST-AUDIT-DEPLOYED: "
                + ", ".join(post_audit)
            )
        if pin_unresolvable:
            print(
                f"[post-audit-detector] WARNING: {len(pin_unresolvable)} PIN-UNRESOLVABLE: "
                + ", ".join(pin_unresolvable)
            )

    if args.json:
        print(json.dumps(summary, indent=2))

    # Exit 1 if any critical issues found
    if post_audit or pin_unresolvable:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
