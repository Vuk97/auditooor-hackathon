#!/usr/bin/env python3
"""
auto-draft-generator.py — Generate complete submission drafts from CCIA attack angles

Reads CCIA attack angles and produces a fully structured submission draft
with rubric citation, dollar impact, OOS clause, originality reference,
and PoC scaffolding. Integrates with poc-scaffold.py for test generation.

Usage:
    auto-draft-generator.py <workspace> --angle-id A-REENT --contract CTFExchange --func cancelOrder
    auto-draft-generator.py <workspace> --angle-id A-ORACLE --contract UmaCtfAdapter --func resolve
    auto-draft-generator.py <workspace> --ccia-json ccia_report.json --pick              # interactive pick
    auto-draft-generator.py <workspace> --ccia-json ccia_report.json --pick-index 1      # non-interactive pick

Output:
    - submissions/staging/<draft-name>.md
    - poc-tests/<PoC-name>.t.sol (if --with-poc)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent
SCAFFOLD_TOOL = AUDITOOOR_DIR / "tools" / "poc-scaffold.py"
PRE_SUBMIT_TOOL = AUDITOOOR_DIR / "tools" / "pre-submit-check.sh"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _impact_contract_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    rows = payload.get("contracts") or payload.get("rows") or payload.get("impact_contracts") or []
    return [row for row in rows if isinstance(row, dict)]


def _suggest_check31_for_impact(impact_id: str):
    """Lazy bridge to program-impact-mapping-check.suggest_check31_for_impact
    (cross-wire #2/#3). Returns (tier, rubric_row_hint) or None; fail-open None
    when the module is unavailable so an older tree is unchanged."""
    try:
        import importlib.util
        tp = Path(__file__).resolve().with_name("program-impact-mapping-check.py")
        spec = importlib.util.spec_from_file_location("_pim_check", tp)
        m = importlib.util.module_from_spec(spec)
        sys.modules["_pim_check"] = m  # py3.14: dataclass needs module registered
        spec.loader.exec_module(m)  # type: ignore
        return m.suggest_check31_for_impact(impact_id)
    except Exception:
        return None


def require_locked_impact_contract(
    ws: Path,
    angle: Dict[str, Any],
    contract: str,
    impact_contract_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Fail closed unless the draft target cites a proved exact impact contract."""
    requested_id = (impact_contract_id or angle.get("impact_contract_id") or "").strip()
    if not requested_id:
        raise ValueError(
            "blocked_missing_impact_contract: auto-draft-generator requires "
            "--impact-contract-id or angle.impact_contract_id before writing drafts or PoC scaffolds"
        )

    path = ws / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        raise ValueError(f"blocked_missing_impact_contract: missing {path}")
    try:
        rows = _impact_contract_rows(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"blocked_missing_impact_contract: invalid {path}: {exc}") from exc

    row = next((r for r in rows if str(r.get("impact_contract_id") or "").strip() == requested_id), None)
    if not row:
        raise ValueError(
            "blocked_missing_impact_contract: impact_contract_id "
            f"{requested_id!r} was not found in {path}"
        )

    # Cross-wire #3: when the impact contract carries the hunt-time impact-
    # methodology class (impact_id / impact_class) but NO human-typed
    # selected_impact, derive selected_impact + severity from the Check#31 table
    # so a lead that only knows its impact class is not hard-blocked. Check #31
    # still verbatim-validates the derived row against the program SEVERITY.md, and
    # the OTHER hard requirements (exact_impact_row / listed_impact_proven /
    # proof_artifact) are unchanged - so this never bypasses proof, it only fills
    # the row-label from the lead's class.
    _impact_id = str(row.get("impact_id") or row.get("impact_class") or "").strip()
    if _impact_id and not str(
        row.get("selected_impact") or row.get("listed_impact_selected") or ""
    ).strip():
        _sugg = _suggest_check31_for_impact(_impact_id)
        if _sugg:
            row.setdefault("selected_impact", _sugg[1])
            if not str(row.get("severity") or row.get("severity_implied") or "").strip():
                row["severity_implied"] = _sugg[0]
            row["impact_derived_from"] = "impact-methodology:" + _impact_id.lower()

    missing: List[str] = []
    if not str(row.get("selected_impact") or row.get("listed_impact_selected") or "").strip():
        missing.append("selected_impact")
    severity = str(row.get("severity") or row.get("raw_severity") or row.get("severity_implied") or "").strip()
    if not severity or severity.lower() == "none":
        missing.append("severity")
    if not _truthy(row.get("exact_impact_row")):
        missing.append("exact_impact_row=true")
    if not _truthy(row.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")
    proof_artifact = str(row.get("proof_artifact") or row.get("proof_path") or "").strip()
    if not proof_artifact:
        missing.append("proof_artifact")
    else:
        proof_path = Path(proof_artifact).expanduser()
        candidates = [proof_path] if proof_path.is_absolute() else [ws / proof_path]
        if not any(path.is_file() for path in candidates):
            missing.append("proof_artifact=file_exists")

    row_contract = str(row.get("contract") or "").strip()
    if row_contract and row_contract != contract:
        missing.append(f"contract={contract}")
    row_angle_id = str(row.get("angle_id") or "").strip()
    if row_angle_id and row_angle_id != str(angle.get("id") or "").strip():
        missing.append(f"angle_id={angle.get('id')}")

    if missing:
        raise ValueError(
            "blocked_missing_impact_contract: impact_contract_id "
            f"{requested_id!r} is not locked to this draft target "
            f"(missing/mismatch: {', '.join(missing)})"
        )
    return row


def load_ccia_angles(ws: Path) -> List[Dict[str, Any]]:
    """Load attack angles from workspace CCIA report."""
    json_path = ws / "ccia_report.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        if isinstance(data, list):
            return data
        return data.get("attack_angles", [])
    # Try markdown
    md_path = ws / "ccia_report.md"
    if md_path.exists():
        return parse_angles_from_md(md_path.read_text())
    return []


def parse_angles_from_md(text: str) -> List[Dict]:
    """Extract attack angles from markdown CCIA report."""
    angles = []
    lines = text.splitlines()
    for line in lines:
        m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
        if m:
            angles.append({
                "id": m.group(1),
                "severity": m.group(2),
                "title": m.group(3),
            })
    return angles


def pick_angle(angles: List[Dict]) -> Dict:
    """Interactive picker for attack angles."""
    if not sys.stdin.isatty():
        raise ValueError(
            "blocked_interactive_pick_requires_tty: --pick requires an interactive terminal; "
            "use --angle-id or --pick-index for non-interactive automation"
        )
    print("Available attack angles:")
    for i, a in enumerate(angles, 1):
        print(f"  {i}. [{a['severity']}] {a['id']} — {a['title']}")
    while True:
        choice = input("Pick angle number (or q to quit): ").strip()
        if choice.lower() == 'q':
            sys.exit(0)
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(angles):
                return angles[idx]
        except ValueError:
            pass
        print("Invalid choice. Try again.")


def pick_angle_by_index(angles: List[Dict], raw_index: int) -> Dict:
    """Select a 1-based angle index without prompting."""
    idx = raw_index - 1
    if idx < 0 or idx >= len(angles):
        raise ValueError(
            f"blocked_invalid_pick_index: --pick-index must be between 1 and {len(angles)}"
        )
    return angles[idx]


def infer_bug_class(angle_id: str) -> str:
    """Map angle ID to bug class description."""
    mapping = {
        "A-REENT": "reentrancy",
        "A-ORACLE": "oracle manipulation / stale price",
        "A-ERC4626": "ERC4626 share price manipulation / inflation attack",
        "A-FLASH": "flash loan reentrancy / callback manipulation",
        "A-TIMESTAMP": "block.timestamp dependence",
        "A-DELEGATE": "delegatecall hijack / arbitrary code execution",
        "A-AUTH": "missing access control / unauthenticated state write",
        "A-UPGRADE": "upgradeable contract gap / storage collision",
        "A-RACE": "cross-contract state race / TOCTOU",
        "A-TXORIGIN": "tx.origin authentication bypass",
    }
    return mapping.get(angle_id, "vulnerability")


def infer_rubric_citation(severity: str, bug_class: str) -> str:
    """Generate a rubric citation paragraph."""
    citations = {
        "reentrancy": (
            "This finding maps to the rubric under **Reentrancy** — external call "
            "before state update allows callback manipulation. The impact is fund "
            "loss via atomic extraction in a single transaction."
        ),
        "oracle": (
            "This finding maps to the rubric under **Oracle Manipulation** — stale "
            "or unvalidated price data consumed in arithmetic operations. The impact "
            "is incorrect valuation leading to fund loss or unfair liquidation."
        ),
        "ERC4626": (
            "This finding maps to the rubric under **Vault Manipulation** — share "
            "price inflation via direct donation or rounding exploitation. The impact "
            "is depositor fund loss via share dilution."
        ),
        "flash": (
            "This finding maps to the rubric under **Reentrancy** — flash loan callback "
            "re-enters protocol before state synchronization. The impact is fund extraction "
            "or state corruption in a single atomic transaction."
        ),
        "timestamp": (
            "This finding maps to the rubric under **Timing / MEV** — block.timestamp "
            "used in conditional without oracle or commit-reveal safeguard. The impact "
            "is time-based check bypass allowing premature execution or delayed settlement."
        ),
        "delegatecall": (
            "This finding maps to the rubric under **Privilege Escalation** — delegatecall "
            "to mutable or attacker-controlled address runs code in caller's storage context. "
            "The impact is full contract takeover or selfdestruct."
        ),
        "access control": (
            "This finding maps to the rubric under **Access Control** — public/external "
            "function modifies critical state without authentication. The impact is "
            "unauthorized state corruption or privilege escalation."
        ),
    }
    for key, citation in citations.items():
        if key in bug_class.lower():
            return citation
    return (
        f"This finding maps to the rubric under **{severity} severity** — the vulnerability "
        f"allows unauthorized manipulation of protocol state or extraction of value."
    )


def infer_dollar_impact(severity: str, bug_class: str) -> str:
    """Generate a dollar impact paragraph."""
    if severity.upper() in ("HIGH", "CRITICAL"):
        return (
            "**Dollar impact:** Direct fund theft is possible. Assuming the protocol holds "
            "$X in TVL (refer to Dune/DeFiLlama for current figure), a permissionless attacker "
            "could extract up to the full vulnerable pool balance. Even partial exploitation "
            "represents a material loss to depositors."
        )
    elif "reentrancy" in bug_class.lower() or "flash" in bug_class.lower():
        return (
            "**Dollar impact:** Reentrancy allows repeated extraction within a single transaction. "
            "The extractable value is bounded by the collateral held in the vulnerable contract. "
            "For protocols with >$1M TVL, this represents a material Medium-to-High severity risk."
        )
    elif "oracle" in bug_class.lower():
        return (
            "**Dollar impact:** Stale oracle prices cause incorrect valuations. In a liquidation "
            "context, this can lead to unfair liquidations worth 5-10% of position size. At scale, "
            "this affects all positions using the oracle — potentially $X in total exposure."
        )
    elif "ERC4626" in bug_class.lower() or "vault" in bug_class.lower():
        return (
            "**Dollar impact:** Share price inflation attacks extract value from depositors. "
            "The attacker profit is bounded by the deposit amount of subsequent depositors. "
            "In a vault with >$100K deposits, this represents a direct loss to users."
        )
    else:
        return (
            "**Dollar impact:** The vulnerability allows unauthorized manipulation of protocol state. "
            "While direct fund theft may require additional preconditions, the corrupted state can "
            "lead to DOS, incorrect accounting, or downstream fund loss."
        )


def infer_mitigation(bug_class: str) -> str:
    """Generate a mitigation paragraph."""
    mitigations = {
        "reentrancy": (
            "1. Implement Checks-Effects-Interactions pattern: update all state variables "
            "before any external call.\n"
            "2. Add ReentrancyGuard (nonReentrant modifier) to functions with external calls.\n"
            "3. Consider using pull-over-push for fund transfers."
        ),
        "oracle": (
            "1. Validate oracle freshness: require `block.timestamp - updatedAt < heartbeat`.\n"
            "2. Use multiple oracle sources and take the median or compare for deviation.\n"
            "3. Implement circuit breakers for extreme price movements."
        ),
        "ERC4626": (
            "1. Track total assets internally rather than relying on direct balanceOf.\n"
            "2. Use virtual shares/offsets to prevent inflation attacks on empty vaults.\n"
            "3. Round deposit shares down and redeem assets up in favor of the vault."
        ),
        "flash": (
            "1. Apply ReentrancyGuard to flash loan callback handlers.\n"
            "2. Update protocol state before issuing the flash loan.\n"
            "3. Validate callback sender is the expected flash loan provider."
        ),
        "timestamp": (
            "1. Use block.number instead of block.timestamp where practical.\n"
            "2. Integrate an oracle or commit-reveal scheme for time-sensitive operations.\n"
            "3. Add a minimum block delay between state-changing actions."
        ),
        "delegatecall": (
            "1. Make delegatecall targets immutable or governed by a timelock.\n"
            "2. Verify target contract hash before delegation.\n"
            "3. Avoid delegatecall in contracts holding user funds."
        ),
        "access control": (
            "1. Add appropriate access control modifiers (onlyOwner, onlyRole, etc.).\n"
            "2. Use OpenZeppelin's AccessControl for role-based permissions.\n"
            "3. Audit all public/external state-writing functions for missing auth."
        ),
    }
    for key, mit in mitigations.items():
        if key in bug_class.lower():
            return mit
    return (
        "1. Review the vulnerable code path for missing validations.\n"
        "2. Add appropriate guards or preconditions.\n"
        "3. Consider security review of related functions."
    )


def generate_draft(
    angle: Dict,
    contract: str,
    func: Optional[str],
    ws: Path,
    poc_path: Optional[str] = None,
    impact_contract: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a complete submission draft markdown."""
    bug_class = infer_bug_class(angle["id"])
    severity = angle.get("severity", "Medium")
    title = angle.get("title", f"{bug_class} in {contract}")
    # Clean up title for filename
    safe_title = re.sub(r'[^\w\-]', '_', title)[:60]

    # Extract contracts mentioned
    contracts = angle.get("contracts", [contract])
    contracts_str = ", ".join(f"`{c}`" for c in contracts)

    rubric = infer_rubric_citation(severity, bug_class)
    dollar = infer_dollar_impact(severity, bug_class)
    mitigation = infer_mitigation(bug_class)

    func_str = f".{func}" if func else ""
    target = f"{contract}{func_str}"

    lines = [
        f"# {title}",
        "",
        f"**Severity:** {severity}",
        f"**Target:** {contracts_str}",
    ]
    if impact_contract:
        lines.append(f"**Impact contract:** `{impact_contract['impact_contract_id']}`")
        selected_impact = impact_contract.get("selected_impact") or impact_contract.get("listed_impact_selected")
        if selected_impact:
            lines.append(f"**Locked impact:** {selected_impact}")
        proof_artifact = impact_contract.get("proof_artifact") or impact_contract.get("proof_path")
        if proof_artifact:
            lines.append(f"**Proof artifact:** `{proof_artifact}`")
    lines.extend([
        "",
        "## Summary",
        f"{contract} contains a {bug_class} vulnerability in `{target}`. "
        f"An attacker can exploit this to [DESCRIBE IMPACT — e.g., extract funds, corrupt state, bypass checks].",
        "",
        "## Rubric Citation",
        rubric,
        "",
        "## Description",
        f"The `{target}` function [DESCRIBE WHAT IT DOES AND WHY IT'S VULNERABLE]. "
        f"Specifically, [DESCRIBE THE BUG WITH FILE:LINE CITATIONS].",
        "",
        "**Attack sequence:**",
        "1. [Attacker does X]",
        "2. [Contract responds with Y]",
        "3. [Attacker profits from Z]",
        "",
        dollar,
        "",
        "## Proof of Concept",
    ])

    if poc_path:
        lines.append(f"See `{poc_path}` for a runnable Foundry test demonstrating the exploit.")
    else:
        lines.append("[TODO: Add PoC test or describe the concrete exploit path]")

    lines.extend([
        "",
        "### Test output",
        "```",
        "[TODO: paste forge test output here]",
        "```",
        "",
        "## What the PoC proves",
        "[MAP EACH TEST TO THE CLAIM IT ESTABLISHES - e.g. 'test A proves the entrypoint "
        "never caps (len==N, zero rejections); test B proves the only defense evicts by X, "
        "not by Y'. Name the negative control. Copy-paste triagers scan for this heading.]",
        "",
        "## Recommended Mitigation",
        mitigation,
        "",
        "## OOS Check",
        "- [ ] This finding does not fall under any out-of-scope clause in the bounty terms.",
        "- [ ] The attack path is accessible to non-privileged users.",
        "",
        "## Originality Check",
        "- [ ] Searched prior audits and corpus — no direct duplicate found.",
        "- [ ] Distinct from prior findings: [EXPLAIN WHY IF NEAR VARIANT].",
        "",
    ])

    # Cross-chain acknowledgment if relevant
    if any(x in str(ws).lower() for x in ("snowbridge", "bridge", "cross-chain", "layerzero")):
        lines.extend([
            "## Cross-Chain Atomicity",
            "- [ ] Acknowledged: operations are atomic within a single cross-chain transaction.",
            "- [ ] Attack spans transaction boundaries or trust domains.",
            "",
        ])

    lines.extend([
        "## Severity Justification",
        f"**{severity}** — [EXPLAIN WHY THIS SEVERITY IS APPROPRIATE BASED ON IMPACT AND LIKELIHOOD].",
        "",
        "---",
        f"*Draft generated by auto-draft-generator.py on {datetime.now(timezone.utc).isoformat()}*",
    ])

    return "\n".join(lines), safe_title


def generate_poc(angle: Dict, contract: str, func: Optional[str], ws: Path) -> Optional[str]:
    """Generate PoC test using poc-scaffold.py."""
    if not SCAFFOLD_TOOL.exists():
        return None

    poc_name = f"PoC_{angle['id']}_{contract}"
    if func:
        poc_name += f"_{func}"
    poc_name += ".t.sol"

    poc_dir = ws / "poc-tests"
    poc_dir.mkdir(exist_ok=True)
    poc_path = poc_dir / poc_name

    args = [
        sys.executable, str(SCAFFOLD_TOOL),
        "--pattern", angle["id"],
        "--contract", contract,
        "--out", str(poc_path),
    ]
    if func:
        args.extend(["--func", func])

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode == 0 and poc_path.exists():
        return str(poc_path.relative_to(ws))
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Auto-draft generator from CCIA angles")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--angle-id", help="CCIA angle ID (e.g., A-REENT)")
    parser.add_argument("--contract", help="Target contract name")
    parser.add_argument("--func", help="Target function name")
    parser.add_argument("--ccia-json", help="Path to CCIA JSON report")
    parser.add_argument("--pick", action="store_true", help="Interactive angle picker")
    parser.add_argument("--pick-index", type=int, help="Non-interactive 1-based angle index selector")
    parser.add_argument("--with-poc", action="store_true", help="Also generate PoC scaffold")
    parser.add_argument("--impact-contract-id", help="Required proved exact impact contract ID")
    parser.add_argument("--out", help="Output file path (default: auto-named in submissions/staging/)")
    parser.add_argument("--dry-run", action="store_true", help="Print draft without writing")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[draft] Error: workspace not found: {ws}")
        sys.exit(1)

    # Load angles
    if args.ccia_json:
        angles = json.loads(Path(args.ccia_json).read_text())
        if isinstance(angles, dict):
            angles = angles.get("attack_angles", [])
    else:
        angles = load_ccia_angles(ws)

    if not angles:
        print(f"[draft] No attack angles found. Run CCIA first:")
        print(f"  python3 tools/ccia.py {ws} --out {ws}/ccia_report.json")
        sys.exit(1)

    # Select angle
    if args.pick and args.pick_index is not None:
        print("[draft] Specify only one of --pick, --pick-index, or --angle-id")
        sys.exit(1)
    if args.pick and args.angle_id:
        print("[draft] Specify only one of --pick, --pick-index, or --angle-id")
        sys.exit(1)
    if args.pick_index is not None and args.angle_id:
        print("[draft] Specify only one of --pick, --pick-index, or --angle-id")
        sys.exit(1)

    if args.pick:
        try:
            angle = pick_angle(angles)
        except ValueError as exc:
            print(f"[draft] {exc}")
            sys.exit(2)
    elif args.pick_index is not None:
        try:
            angle = pick_angle_by_index(angles, args.pick_index)
        except ValueError as exc:
            print(f"[draft] {exc}")
            sys.exit(2)
    elif args.angle_id:
        matches = [a for a in angles if a["id"] == args.angle_id]
        if not matches:
            print(f"[draft] Angle {args.angle_id} not found. Available: {', '.join(set(a['id'] for a in angles))}")
            sys.exit(1)
        angle = matches[0]
    else:
        print("[draft] Specify --angle-id or --pick")
        sys.exit(1)

    contract = args.contract or (angle.get("contracts", ["UNKNOWN"])[0])
    func = args.func

    print(f"[draft] Generating draft for {angle['id']} — {angle['title']}")
    try:
        impact_contract = require_locked_impact_contract(ws, angle, contract, args.impact_contract_id)
    except ValueError as exc:
        print(f"[draft] {exc}")
        sys.exit(2)

    # Generate PoC if requested
    poc_rel_path = None
    if args.with_poc:
        poc_rel_path = generate_poc(angle, contract, func, ws)
        if poc_rel_path:
            print(f"[draft] PoC scaffold: {ws}/{poc_rel_path}")

    # Generate draft
    draft_text, safe_title = generate_draft(angle, contract, func, ws, poc_rel_path, impact_contract)

    if args.dry_run:
        print("\n" + "=" * 70)
        print(draft_text)
        print("=" * 70)
        sys.exit(0)

    # Write draft
    out_dir = ws / "submissions" / "staging"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or (out_dir / f"draft_{safe_title}.md")
    out_path = Path(out_path)
    out_path.write_text(draft_text)
    print(f"[draft] Written: {out_path}")

    # Run pre-submit check
    if PRE_SUBMIT_TOOL.exists():
        print(f"[draft] Running pre-submit check...")
        result = subprocess.run(
            ["bash", str(PRE_SUBMIT_TOOL), str(out_path)],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"[draft] Pre-submit check failed — fix before submitting")
        else:
            print(f"[draft] Pre-submit check passed (or soft warnings only)")


if __name__ == "__main__":
    main()
