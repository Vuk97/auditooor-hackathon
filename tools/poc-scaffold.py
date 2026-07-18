#!/usr/bin/env python3
"""
poc-scaffold.py — Pattern-based PoC scaffold generator

Given a CCIA attack angle (or pattern ID), generates a Foundry test scaffold
specific to that bug class. Saves hours of boilerplate writing.

Usage:
    poc-scaffold.py --pattern A-REENT --contract CTFExchange --func cancelOrder --out poc-tests/ReentrancyCTFExchange.t.sol
    poc-scaffold.py --pattern A-ORACLE --contract UmaCtfAdapter --func resolve --out poc-tests/OracleStalePrice.t.sol
    poc-scaffold.py --pattern A-ERC4626 --contract ShareToken --out poc-tests/ERC4626Inflation.t.sol
    poc-scaffold.py --pattern A-FLASH --contract FlashLender --out poc-tests/FlashLoanReentrancy.t.sol
    poc-scaffold.py --pattern A-TIMESTAMP --contract NegRiskOperator --func resolveQuestion --out poc-tests/TimestampManip.t.sol

The generated scaffolds include:
  - Setup with mocked/external contracts
  - The attack sequence specific to the bug class
  - Assert comments explaining WHY each assert is a bug
  - Placeholders for project-specific imports and addresses
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Local import: poc-scaffold raises an artifact's evidence_class to
# ``scaffolded_unverified`` (item #14). The scaffold is a starting point,
# not proof; downstream consumers must wait for poc-execution-record to
# raise it again to ``executed_with_manifest``.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402


SCAFFOLDS = {
    "A-REENT": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// TODO: replace with actual project imports
// import "{contract_path}";

/**
 * @title Reentrancy PoC — {contract}.{func}
 * @notice Bug class: Cross-contract reentrancy via external call before state write
 * @dev Steps:
 *   1. Attacker contract implements {callback_func} callback
 *   2. Attacker calls {contract}.{func} triggering external call
 *   3. Callback re-enters {contract} before state is updated
 *   4. Attacker extracts value during reentrant call
 */
contract ReentrancyPoC_{contract} is Test {
    // TODO: deploy or import actual contracts
    // {contract} target;
    Attacker attacker;

    function setUp() public override {
        // TODO: deploy target contract with real dependencies
        // target = new {contract}();
        attacker = new Attacker();
    }

    function test_reentrancy_extractsValue() public {
        // Arrange: attacker needs to have a position/collateral
        // TODO: mint/give attacker the prerequisite tokens/position

        uint256 balanceBefore = address(attacker).balance; // or token balance

        // Act: attacker triggers the vulnerable path
        // attacker.attack(target);

        uint256 balanceAfter = address(attacker).balance;

        // Assert: attacker extracted value without authorization
        // This is the bug: the callback allowed reentrant extraction
        assertGt(balanceAfter, balanceBefore, "Attacker should have extracted value via reentrancy");
    }
}

contract Attacker {
    // TODO: track reentrancy depth to prevent infinite loop
    uint256 public attackCount;

    // TODO: replace with actual callback signature
    function {callback_func}() external returns (bytes4) {
        attackCount++;
        if (attackCount < 2) {
            // TODO: re-enter the vulnerable function here
            // ITarget(msg.sender).{func}();
        }
        return this.{callback_func}.selector;
    }
}
""",

    "A-ORACLE": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Oracle Stale Price Manipulation PoC — {contract}.{func}
 * @notice Bug class: Oracle price consumed without staleness/heartbeat validation
 * @dev Steps:
 *   1. Oracle returns stale price (simulate old timestamp)
 *   2. {contract}.{func} uses stale price in arithmetic
 *   3. Attacker profits from price discrepancy
 */
contract OracleStalePricePoC_{contract} is Test {
    // TODO: deploy or import actual contracts
    // MockOracle oracle;
    // {contract} target;

    function setUp() public {
        // TODO: deploy mock oracle and target
        // oracle = new MockOracle();
        // target = new {contract}(address(oracle));
    }

    function test_stalePriceCausesBadArithmetic() public {
        // Arrange: set oracle to an old stale price
        // oracle.setPrice(100e18, block.timestamp - 7 days); // stale by 7 days

        // Act: call function that consumes oracle without staleness check
        // uint256 result = target.{func}();

        // Assert: if price were fresh, result would differ
        // This is the bug: no staleness check means stale price is trusted
        // assertEq(result, expectedBadValue, "Function accepted stale oracle price");
    }

    function test_priceWithHeartbeatCheckWouldRevert() public {
        // Arrange: set oracle to an old stale price
        // oracle.setPrice(100e18, block.timestamp - 7 days);

        // Act & Assert: a properly guarded function would reject this
        // vm.expectRevert("stale price");
        // target.{func}();
    }
}
""",

    "A-ERC4626": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title ERC4626 Share Price Manipulation PoC — {contract}
 * @notice Bug class: Vault share price manipulation via donation/inflation attack
 * @dev Steps:
 *   1. Attacker donates assets to vault (inflates totalAssets)
 *   2. Victim deposits at inflated share price (receives fewer shares)
 *   3. Attacker redeems shares at inflated rate, extracting victim's deposit
 */
contract ERC4626InflationPoC_{contract} is Test {
    // TODO: deploy or import actual vault
    // {contract} vault;
    // ERC20Mock asset;

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // TODO: deploy asset and vault
        // asset = new ERC20Mock();
        // vault = new {contract}(address(asset));
    }

    function test_donationInflatesSharePrice() public {
        // Arrange: victim approves vault
        // vm.prank(victim);
        // asset.approve(address(vault), 1000e18);

        // Step 1: attacker donates directly to vault (no shares minted)
        // vm.prank(attacker);
        // asset.transfer(address(vault), 1000e18);

        // Step 2: victim deposits — should get fewer shares due to inflated totalAssets
        // vm.prank(victim);
        // uint256 shares = vault.deposit(1000e18, victim);

        // Assert: victim got fewer shares than fair price
        // uint256 fairShares = 1000e18; // 1:1 if no donation
        // assertLt(shares, fairShares, "Donation inflated share price — victim received fewer shares");

        // Step 3: attacker redeems 1 wei of shares (or all if they have some)
        // This demonstrates the extraction vector
    }

    function test_roundingDirectionFavorsAttacker() public {
        // Arrange: small deposit to create rounding edge case
        // vm.prank(victim);
        // asset.approve(address(vault), 1e18);

        // Act: deposit at edge of rounding
        // vm.prank(victim);
        // uint256 shares = vault.deposit(1e18, victim);

        // Assert: rounding should favor vault (round down shares, round up assets)
        // If rounding favors attacker, that's the bug
        // assertGe(shares, expectedMinimum, "Rounding direction favors attacker");
    }
}
""",

    "A-FLASH": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Flash Loan Reentrancy PoC — {contract}.{func}
 * @notice Bug class: Flash loan callback allows reentrancy before state update
 * @dev Steps:
 *   1. Attacker takes flash loan
 *   2. During callback, re-enters protocol before state is updated
 *   3. Attacker manipulates state or extracts value
 *   4. Repays flash loan
 */
contract FlashLoanReentrancyPoC_{contract} is Test {
    // TODO: deploy or import actual contracts
    // FlashLender lender;
    // {contract} target;
    Attacker attacker;

    function setUp() public {
        // TODO: deploy lender and target
        // lender = new FlashLender();
        // target = new {contract}();
        attacker = new Attacker();
    }

    function test_flashLoanCallbackReenters() public {
        // Arrange: give lender some liquidity
        // deal(address(asset), address(lender), 10000e18);

        uint256 balanceBefore = address(attacker).balance;

        // Act: attacker requests flash loan
        // vm.prank(address(attacker));
        // lender.flashLoan(attacker, 1000e18, "");

        uint256 balanceAfter = address(attacker).balance;

        // Assert: attacker extracted value during callback reentrancy
        assertGt(balanceAfter, balanceBefore, "Attacker extracted value via flash-loan callback reentrancy");
    }
}

contract Attacker is IERC3156FlashBorrower {
    uint256 public callbackCount;

    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        returns (bytes32)
    {
        callbackCount++;
        if (callbackCount < 2) {
            // TODO: re-enter vulnerable function here
            // ITarget(msg.sender).{func}();
        }
        // TODO: approve repayment
        // IERC20(token).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

interface IERC3156FlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external returns (bytes32);
}
""",

    "A-TIMESTAMP": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Timestamp Manipulation PoC — {contract}.{func}
 * @notice Bug class: block.timestamp used in conditional without safeguard
 * @dev Steps:
 *   1. Warp block.timestamp to manipulate time-based condition
 *   2. Call {contract}.{func}
 *   3. Function accepts manipulated timestamp as valid
 */
contract TimestampManipPoC_{contract} is Test {
    // TODO: deploy or import actual contract
    // {contract} target;

    function setUp() public {
        // TODO: deploy target
        // target = new {contract}();
    }

    function test_timestampManipulationBypassesCheck() public {
        // Arrange: warp to a timestamp that bypasses the check
        // For example, if check is 'block.timestamp > deadline', warp past deadline
        // vm.warp(block.timestamp + 1 days);

        // Act: call the time-dependent function
        // bool result = target.{func}();

        // Assert: the manipulated timestamp was accepted
        // assertTrue(result, "Timestamp manipulation bypassed time check");

        // This is the bug: miners can shift timestamps ~15s, and validators
        // can choose timestamps within a window. No oracle/commit-reveal = exploitable.
    }

    function test_freshTimestampWouldFail() public {
        // Arrange: keep current timestamp (not manipulated)
        // uint256 legitTime = block.timestamp;

        // Act & Assert: at legit time, the check should pass or fail as designed
        // vm.warp(legitTime);
        // bool result = target.{func}();
        // assertFalse(result, "At legit time, check should fail (proving time dependency)");
    }
}
""",

    "A-DELEGATE": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Delegatecall Hijack PoC — {contract}.{func}
 * @notice Bug class: delegatecall to mutable/compromised address
 * @dev Steps:
 *   1. Attacker changes delegatecall target (if mutable)
 *   2. Target contract contains selfdestruct or malicious logic
 *   3. {contract}.{func} delegates to attacker-controlled code
 */
contract DelegatecallHijackPoC_{contract} is Test {
    // TODO: deploy or import actual contracts
    // {contract} target;
    // MaliciousLogic malicious;

    function setUp() public {
        // TODO: deploy target and malicious logic
        // malicious = new MaliciousLogic();
        // target = new {contract}();
    }

    function test_delegatecallToAttackerControlledCode() public {
        // Arrange: if target address is mutable, set it to malicious contract
        // vm.prank(attacker);
        // target.setImplementation(address(malicious));

        // Act: trigger delegatecall
        // vm.prank(attacker);
        // target.{func}();

        // Assert: malicious logic executed in target's context
        // assertTrue(malicious.wasCalled(), "Delegatecall executed attacker-controlled code");

        // This is the bug: delegatecall runs code in caller's storage context.
        // If target is mutable, attacker can hijack the contract entirely.
    }
}

contract MaliciousLogic {
    bool public wasCalled;

    function malicious() external {
        wasCalled = true;
        // Could also: selfdestruct(payable(msg.sender));
    }
}
""",

    "A-AUTH": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Unauthenticated State Write PoC — {contract}.{func}
 * @notice Bug class: Public/external function writes state without access control
 * @dev Steps:
 *   1. Any address calls {contract}.{func}
 *   2. Function modifies critical state (balances, roles, config)
 *   3. No onlyOwner/onlyAdmin/auth modifier prevents this
 */
contract UnauthStateWritePoC_{contract} is Test {
    // TODO: deploy or import actual contract
    // {contract} target;

    address attacker = makeAddr("attacker");

    function setUp() public {
        // TODO: deploy target
        // target = new {contract}();
    }

    function test_anyoneCanWriteState() public {
        // Arrange: read state before attack
        // uint256 stateBefore = target.criticalState();

        // Act: attacker (unauthorized) calls the function
        // vm.prank(attacker);
        // target.{func}(...);

        // Assert: state was modified by unauthorized caller
        // uint256 stateAfter = target.criticalState();
        // assertNotEq(stateAfter, stateBefore, "Unauthorized caller modified state");

        // This is the bug: no access control means any user can change critical state.
    }
}
""",
}


PLAN_SCAFFOLD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
{extra_imports}

{support_contracts}

/**
 * @title Candidate PoC Plan — {contract} {angle_id}
 * @notice Generated from a proof-rich swarm candidate plan ({kind})
 * @dev Source artifact: {source_file}
 * @dev Angle title: {angle_title}
 * @dev Suggested functions: {suggested_functions}
 * @dev Recommended next step: {recommended_next_step}
 */
contract CandidatePlanPoC_{contract}_{angle_slug} is {contract_base} {
    // TODO: replace with actual project imports and deployed contract bindings
    // {contract} target;
{state_var_lines}
{actor_lines}

    function setUp() public override {
        _initResolutionOnlyHarness();
        // TODO: deploy/import the live contracts for {contract}
        // TODO: confirm the live-proof premises below before attempting the exploit
{setup_assertions}
{fixture_hint}
    }

{helper_lines}

    function test_candidatePlan_{angle_slug}() public {
        // Exploit Goal:
{exploit_goal_lines}

        // Matched mining brief(s):
{matched_brief_lines}

        // Paired live-proof rows:
{paired_row_lines}

        // Suggested interleaving sequence:
{interleaving_lines}

        require(address(nrOperator) != address(0), "wire operator");

        // Baseline path lifted from the strongest existing exploit corpus for this seam.
{baseline_execution_lines}

        // TODO: fork the relevant chain / pin the block used by live proof
        // TODO: extend beyond the baseline by wiring the broader `_data` /
        //       prepareMarket / prepareQuestion / resolveQuestion interleaving path
        // TODO: demonstrate victim impact or state corruption beyond the known unflag race
{assertion_lines}
    }
}
"""


HERE = Path(__file__).resolve().parent
GEN_COMPOSITION_FUZZ = HERE / "gen-composition-fuzz.sh"


def generate_scaffold(pattern: str, contract: str, func: Optional[str], contract_path: Optional[str]) -> str:
    """Generate a PoC scaffold for the given pattern."""
    scaffold = SCAFFOLDS.get(pattern)
    if not scaffold:
        available = ", ".join(SCAFFOLDS.keys())
        raise ValueError(f"Unknown pattern '{pattern}'. Available: {available}")

    func = func or "vulnerableFunction"
    contract_path = contract_path or f"src/{contract}.sol"

    # Determine likely callback function name for reentrancy patterns
    callback_func = "onERC1155Received"
    if "ERC20" in contract or "Token" in contract:
        callback_func = "onERC20Received"
    elif "721" in contract or "NFT" in contract:
        callback_func = "onERC721Received"

    # Use str.replace instead of .format to avoid conflicts with Solidity braces
    return (scaffold
            .replace("{contract}", contract)
            .replace("{func}", func)
            .replace("{contract_path}", contract_path)
            .replace("{callback_func}", callback_func))


def slugify(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return text or "candidate"


def _candidate_source_location(candidate: Dict[str, Any]) -> str:
    source = candidate.get("source_file") or "unknown-source"
    # Prefer structured source_line / line / source_lineno when present, then
    # gracefully accept an inline 'path:line' form already in source_file.
    line = (
        candidate.get("source_line")
        or candidate.get("source_lineno")
        or candidate.get("line")
    )
    if line is None:
        return str(source)
    return f"{source}:{line}"


def candidate_selector_summary(candidate: Dict[str, Any], index: int) -> str:
    contract = candidate.get("contract") or "?"
    angle_id = candidate.get("angle_id") or "?"
    title = candidate.get("angle_title") or candidate.get("title") or "untitled"
    location = _candidate_source_location(candidate)
    evidence_class = (
        candidate.get("evidence_class")
        or candidate.get("evidence_kind")
        or candidate.get("kind")
        or "unknown"
    )
    return (
        f"[{index}] contract={contract} angle_id={angle_id} "
        f"title={title!r} source={location} evidence_class={evidence_class}"
    )


def format_candidate_selector_help(candidates: List[Dict[str, Any]], indexes: List[int]) -> str:
    if not indexes:
        return "available candidates:\n" + "\n".join(
            f"  {candidate_selector_summary(candidate, index)}"
            for index, candidate in enumerate(candidates)
        )
    return "matching candidates:\n" + "\n".join(
        f"  {candidate_selector_summary(candidates[index], index)}"
        for index in indexes
    )


def load_candidate_plan(
    plan_json: Path,
    contract: Optional[str],
    angle_id: Optional[str],
    candidate_index: Optional[int],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Resolve a candidate from ``plan_json``.

    Returns a tuple ``(candidate, selection_meta)``. ``selection_meta`` carries
    enough information for the scaffold's ambiguity-resolution log:

    - ``selected_index`` (int)
    - ``alternative_indexes`` (list[int]): when ``--candidate-index`` was used
      to disambiguate, lists the other matches that were also valid.
    - ``selector`` (dict): the contract/angle filter the operator passed.
    - ``ambiguity_resolved`` (bool): True when more than one candidate matched
      the selector and ``--candidate-index`` was required to pick one.
    - ``alternatives`` (list[dict]): summary rows for the rejected matches.

    Fails closed (raises ``ValueError``) when 2+ candidates match the
    selector and ``--candidate-index`` was not provided. The helpful error
    message includes each candidate's title, source ``file:line``, and
    ``evidence_class`` so the operator can pick the intended hypothesis.
    """
    data = json.loads(plan_json.read_text())
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError(f"No candidates found in {plan_json}")

    selector = {"contract": contract, "angle_id": angle_id}
    match_indexes: List[int] = []
    for index, candidate in enumerate(candidates):
        if contract and candidate.get("contract") != contract:
            continue
        if angle_id and candidate.get("angle_id") != angle_id:
            continue
        match_indexes.append(index)

    selection_meta: Dict[str, Any] = {
        "selector": selector,
        "selected_index": None,
        "alternative_indexes": [],
        "alternatives": [],
        "ambiguity_resolved": False,
    }

    if candidate_index is not None:
        if candidate_index < 0 or candidate_index >= len(candidates):
            raise ValueError(
                f"Candidate index {candidate_index} out of range "
                f"(0..{len(candidates) - 1})"
            )
        # Honor the explicit pick, but also surface whether the pick was
        # disambiguating among multiple matches so callers can log it.
        candidate = candidates[candidate_index]
        if (contract or angle_id) and candidate_index in match_indexes and len(match_indexes) > 1:
            alternatives = [i for i in match_indexes if i != candidate_index]
            selection_meta["ambiguity_resolved"] = True
            selection_meta["alternative_indexes"] = alternatives
            selection_meta["alternatives"] = [
                _candidate_log_summary(candidates[i], i) for i in alternatives
            ]
        selection_meta["selected_index"] = candidate_index
    else:
        if not match_indexes:
            selector_bits = []
            if contract:
                selector_bits.append(f"contract={contract}")
            if angle_id:
                selector_bits.append(f"angle_id={angle_id}")
            details = ", ".join(selector_bits) if selector_bits else "no selector"
            help_text = format_candidate_selector_help(candidates, [])
            raise ValueError(
                f"No candidate matched ({details}) in {plan_json}\n{help_text}"
            )
        if len(match_indexes) > 1:
            help_text = format_candidate_selector_help(candidates, match_indexes)
            raise ValueError(
                f"Multiple candidates matched in {plan_json}; "
                f"pass --candidate-index <n> to disambiguate\n"
                f"{help_text}\n"
                f"hint: rerun with --candidate-index <n> using one of the "
                f"indexes above. Each row shows the title, source file:line, "
                f"and evidence_class so you can pick the intended hypothesis."
            )
        selection_meta["selected_index"] = match_indexes[0]
        candidate = candidates[match_indexes[0]]

    required = ("contract", "angle_id", "angle_title", "exploit_goal")
    missing = [field for field in required if not candidate.get(field)]
    if missing:
        raise ValueError(
            f"Candidate is missing required field(s): {', '.join(missing)}"
        )
    return candidate, selection_meta


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _explicit_false(value: Any) -> bool:
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "n"}
    if isinstance(value, (int, float)):
        return value == 0
    return False


def _nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _first_text(row: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = _nonempty_text(row.get(key))
        if value:
            return value
    return ""


def _impact_contract_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "records", "rows", "impact_contracts"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _candidate_source_key(row: Dict[str, Any]) -> str:
    source = _first_text(row, ("source", "source_file", "file", "path"))
    line = row.get("source_line") or row.get("line") or row.get("start_line")
    if source and line:
        return f"{source}:{line}"
    return source


def _candidate_match_key(row: Dict[str, Any]) -> str:
    return _first_text(
        row,
        (
            "candidate_id",
            "stable_candidate_id",
            "id",
            "harness_task_id",
            "source_proof_id",
        ),
    )


def _load_workspace_impact_contracts(workspace: Optional[Path]) -> List[Dict[str, Any]]:
    if workspace is None:
        return []
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        return []
    try:
        return _impact_contract_rows(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"blocked_missing_impact_contract: invalid {path}: {exc}")


def _matching_impact_contract(
    candidate: Dict[str, Any],
    workspace: Optional[Path],
) -> Optional[Dict[str, Any]]:
    rows = _load_workspace_impact_contracts(workspace)
    if not rows:
        return None

    explicit = _first_text(candidate, ("impact_contract_id",))
    if explicit:
        for row in rows:
            if _first_text(row, ("impact_contract_id",)) == explicit:
                return row

    candidate_id = _candidate_match_key(candidate)
    if candidate_id:
        for row in rows:
            if _candidate_match_key(row) == candidate_id:
                return row

    source_key = _candidate_source_key(candidate)
    if source_key:
        for row in rows:
            if _candidate_source_key(row) == source_key:
                return row

    contract = _nonempty_text(candidate.get("contract"))
    angle_id = _nonempty_text(candidate.get("angle_id"))
    if contract and angle_id:
        for row in rows:
            if (
                _nonempty_text(row.get("contract")) == contract
                and _nonempty_text(row.get("angle_id")) == angle_id
            ):
                return row

    selected = _nonempty_text(candidate.get("selected_impact")).lower()
    if selected:
        for row in rows:
            if _nonempty_text(row.get("selected_impact")).lower() == selected:
                return row
    return None


def _merged_impact_contract(
    candidate: Dict[str, Any],
    workspace: Optional[Path],
) -> Tuple[Dict[str, Any], bool]:
    matched = _matching_impact_contract(candidate, workspace)
    merged: Dict[str, Any] = {}
    if matched:
        merged.update(matched)
    for key, value in candidate.items():
        if value not in (None, ""):
            merged[key] = value
    return merged, bool(matched)


def require_locked_impact_contract(
    candidate: Dict[str, Any],
    workspace: Optional[Path],
) -> Dict[str, Any]:
    """Fail closed unless a plan candidate is locked to a proved impact row."""
    row, matched_workspace_row = _merged_impact_contract(candidate, workspace)
    missing: List[str] = []

    if not (_first_text(row, ("impact_contract_id",)) or matched_workspace_row):
        missing.append("impact_contract_id_or_workspace_match")
    if not _first_text(row, ("selected_impact", "listed_impact_selected")):
        missing.append("selected_impact")
    severity = _first_text(row, ("severity", "raw_severity", "severity_implied"))
    if not severity or severity.lower() == "none":
        missing.append("severity")
    if _explicit_false(row.get("exact_impact_row")):
        missing.append("exact_impact_row_not_false")
    if not _truthy(row.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")

    if missing:
        candidate_id = _candidate_match_key(candidate) or _candidate_source_key(candidate) or (
            f"{candidate.get('contract', '?')}:{candidate.get('angle_id', '?')}"
        )
        raise ValueError(
            "blocked_missing_impact_contract: selected --plan-json candidate "
            f"{candidate_id} is not locked to a proved exact impact contract "
            f"(missing: {', '.join(missing)})"
        )
    return row


def _candidate_log_summary(candidate: Dict[str, Any], index: int) -> Dict[str, Any]:
    return {
        "index": index,
        "contract": candidate.get("contract"),
        "angle_id": candidate.get("angle_id"),
        "angle_title": candidate.get("angle_title") or candidate.get("title"),
        "source": _candidate_source_location(candidate),
        "evidence_class": (
            candidate.get("evidence_class")
            or candidate.get("evidence_kind")
            or candidate.get("kind")
        ),
    }


AMBIGUITY_LOG_RELPATH = Path(".auditooor") / "poc_scaffold_ambiguity_resolutions.jsonl"


def scaffold_blockers(candidate: Dict[str, Any]) -> List[str]:
    blockers: List[str] = []
    routing = (
        candidate.get("outcome_calibrated_routing")
        if isinstance(candidate.get("outcome_calibrated_routing"), dict)
        else {}
    )
    if routing.get("local_verification_required") is True:
        status = routing.get("routing_status") or "input_only_local_verification_required"
        blockers.append(
            "local verification still required before scaffold emission "
            f"(routing_status={status})"
        )

    allocation_gate = (
        candidate.get("allocation_gate")
        if isinstance(candidate.get("allocation_gate"), dict)
        else {}
    )
    blocked_task_types = {
        str(item)
        for item in (allocation_gate.get("blocked_task_types") or [])
        if str(item).strip()
    }
    if blocked_task_types.intersection({"harness", "poc", "report"}):
        blockers.append(
            "allocation gate still blocks harness/PoC/report work "
            f"(status={allocation_gate.get('status') or 'unknown'})"
        )

    evidence_class = candidate.get("evidence_class")
    if (
        candidate.get("impact_contract_required") is True
        and not str(candidate.get("impact_contract_id") or "").strip()
        and evidence_class in {
            _evidence_class.GENERATED_HYPOTHESIS,
            _evidence_class.SCAFFOLDED_UNVERIFIED,
            None,
            "",
        }
    ):
        blockers.append(
            "exact impact contract is still missing for an advisory-origin candidate"
        )
    return blockers


def _ambiguity_log_root(workspace: Optional[Path], plan_json: Path,
                        out_path: Path) -> Optional[Path]:
    """Pick the most useful workspace root for the ambiguity-resolution log.

    Preference order:
      1. The explicit workspace inferred from the plan-json layout
         (``swarm/...`` -> parent), since that matches how operators run
         ``poc-scaffold.py`` inside a workspace.
      2. ``$AUDITOOOR_AMBIGUITY_LOG_ROOT`` when set (test seam).
      3. The plan-json's parent directory.
    """
    env_root = os.environ.get("AUDITOOOR_AMBIGUITY_LOG_ROOT")
    if workspace is not None:
        return workspace
    if env_root:
        return Path(env_root)
    return plan_json.resolve().parent


def write_ambiguity_resolution_log(
    log_root: Path,
    plan_json: Path,
    out_path: Path,
    candidate: Dict[str, Any],
    selection_meta: Dict[str, Any],
) -> Path:
    """Append one row to the ambiguity-resolution log when the operator used
    ``--candidate-index`` to pick among multiple matching candidates.

    The log is JSONL so closeout (and any auditor reviewing the run) can
    enumerate every disambiguating pick and sanity-check the choice without
    re-running the scaffold.
    """
    log_path = log_root / AMBIGUITY_LOG_RELPATH
    log_path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": "auditooor.poc_scaffold_ambiguity.v1",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plan_json": str(plan_json),
        "out_path": str(out_path),
        "selector": selection_meta.get("selector") or {},
        "selected": _candidate_log_summary(
            candidate, selection_meta.get("selected_index", -1)
        ),
        "alternatives": selection_meta.get("alternatives") or [],
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
    return log_path


def indent_comment_lines(items: List[str], fallback: str) -> str:
    if not items:
        items = [fallback]
    return "\n".join(f"        // {line}" for line in items)


def generate_plan_scaffold(candidate: Dict[str, Any], workspace: Optional[Path] = None,
                           fixture_selection: Optional[Dict[str, Any]] = None) -> str:
    contract = candidate["contract"]
    angle_id = candidate["angle_id"]
    angle_slug = slugify(angle_id)
    exploit_goal_text = candidate["exploit_goal"]
    paired_rows = candidate.get("paired_live_row_ids", [])
    matched_briefs = candidate.get("matched_mining_briefs", [])
    suggested_functions = candidate.get("suggested_functions", [])

    goal_lines = [
        line.strip()
        for line in exploit_goal_text.splitlines()
        if line.strip() and not line.startswith("## ") and line.strip() != "```"
    ]
    goal_comment = indent_comment_lines(goal_lines, "TODO: fill in exploit goal from candidate plan")
    setup_assertions = indent_comment_lines(
        [f"assert live-proof premise from `{row_id}`" for row_id in paired_rows],
        "assert the required live/topology premises before running the exploit path",
    )
    matched_brief_lines = indent_comment_lines(
        [f"source brief: {brief}" for brief in matched_briefs],
        "no matched mining brief recorded",
    )
    paired_row_lines = indent_comment_lines(
        [row_id for row_id in paired_rows],
        "no paired live-proof rows recorded",
    )
    interleaving_lines = indent_comment_lines(
        build_interleaving_steps(contract, candidate.get("angle_id", ""), suggested_functions, workspace),
        "turn the exploit goal into a transaction-level interleaving sequence",
    )
    fixture_hint_lines: List[str] = []
    if fixture_selection is not None:
        if fixture_selection.get("selected"):
            sel = fixture_selection["selected"]
            fixture_hint_lines.append(
                f"selected workspace fixture (score={sel['score']}): {sel['path']}"
            )
            manifest_path = fixture_selection.get("manifest_path")
            if manifest_path:
                fixture_hint_lines.append(f"selection manifest: {manifest_path}")
        else:
            warn = fixture_selection.get("warning") or "no fixture selected"
            fixture_hint_lines.append(f"FIXTURE WARNING: {warn}")
    fixture_hint_lines.extend(existing_fixture_hints(workspace, contract, suggested_functions))
    fixture_hint = indent_comment_lines(
        fixture_hint_lines,
        "search the workspace for the closest snapshot/test fixture before building the exploit harness",
    )
    suggested_functions_str = ", ".join(suggested_functions) if suggested_functions else "none recorded"
    use_neg_risk_adapter_fixture = should_use_neg_risk_adapter_fixture(workspace, contract, angle_id, suggested_functions)
    use_neg_risk_integration_fixture = should_use_neg_risk_integration_fixture(
        workspace,
        contract,
        angle_id,
        suggested_functions,
    )
    use_real_neg_risk_operator = should_use_real_neg_risk_operator(
        workspace,
        contract,
        angle_id,
        suggested_functions,
        use_neg_risk_adapter_fixture or use_neg_risk_integration_fixture,
    )
    if use_neg_risk_integration_fixture:
        contract_base = "IntegrationTest"
    elif use_neg_risk_adapter_fixture:
        contract_base = "NegRiskAdapter_SetUp"
    else:
        contract_base = "Test"
    actor_lines = render_actor_lines(
        contract,
        angle_id,
        suggested_functions,
        use_neg_risk_adapter_fixture,
        use_neg_risk_integration_fixture,
    )
    state_var_lines = render_state_var_lines(
        contract,
        angle_id,
        suggested_functions,
        use_real_neg_risk_operator,
        use_neg_risk_adapter_fixture,
        use_neg_risk_integration_fixture,
    )
    helper_lines = render_helper_lines(
        contract,
        angle_id,
        suggested_functions,
        use_real_neg_risk_operator,
        use_neg_risk_adapter_fixture,
        use_neg_risk_integration_fixture,
    )
    assertion_lines = indent_comment_lines(
        render_assertion_lines(contract, angle_id, suggested_functions),
        "assert victim-impacting state corruption or an irreversible wrong-resolution path",
    )

    return (PLAN_SCAFFOLD
            .replace("{contract}", contract)
            .replace("{angle_id}", angle_id)
            .replace("{angle_title}", candidate["angle_title"])
            .replace("{angle_slug}", angle_slug)
            .replace("{kind}", candidate.get("kind", "poc_plan"))
            .replace("{source_file}", candidate.get("source_file", "unknown"))
            .replace("{suggested_functions}", suggested_functions_str)
            .replace("{recommended_next_step}", candidate.get("recommended_next_step", "implement exploit path"))
            .replace("{contract_base}", contract_base)
            .replace(
                "{extra_imports}",
                render_extra_imports(
                    contract,
                    angle_id,
                    suggested_functions,
                    use_real_neg_risk_operator,
                    use_neg_risk_adapter_fixture,
                    use_neg_risk_integration_fixture,
                ),
            )
            .replace(
                "{support_contracts}",
                render_support_contracts(
                    contract,
                    angle_id,
                    suggested_functions,
                    use_real_neg_risk_operator,
                    use_neg_risk_adapter_fixture,
                    use_neg_risk_integration_fixture,
                ),
            )
            .replace("{state_var_lines}", state_var_lines)
            .replace("{actor_lines}", actor_lines)
            .replace("{setup_assertions}", setup_assertions)
            .replace("{fixture_hint}", fixture_hint)
            .replace("{helper_lines}", helper_lines)
            .replace("{exploit_goal_lines}", goal_comment)
            .replace("{matched_brief_lines}", matched_brief_lines)
            .replace("{paired_row_lines}", paired_row_lines)
            .replace("{interleaving_lines}", interleaving_lines)
            .replace(
                "{baseline_execution_lines}",
                render_baseline_execution_lines(
                    contract,
                    angle_id,
                    suggested_functions,
                    use_neg_risk_adapter_fixture,
                    use_neg_risk_integration_fixture,
                ),
            )
            .replace("{assertion_lines}", assertion_lines))


# ---------------------------------------------------------------------------
# Deterministic fixture scoring (P1-5 burn-down)
# ---------------------------------------------------------------------------
#
# When a candidate plan is scaffolded against a real Foundry workspace we want
# to (a) enumerate any project-supplied test fixtures, (b) pick the one most
# likely to bootstrap the exploit harness via a *documented*, *deterministic*
# score, and (c) emit a JSON manifest with the full ranking so the operator
# (and later auditors) can see exactly why a fixture was chosen.
#
# Previous behaviour was "first match wins" inside `existing_fixture_hints` —
# all scaffolds got a generic NegRisk-flavoured hint regardless of whether the
# project under audit even had those fixtures. This module replaces that with
# an explicit scoring pass and a clear warning when no fixture meets the
# minimum score, so users are never silently fed a generic fallback.
#
# Score breakdown (deterministic, integer-valued, higher is better):
#
#   (a) Shared-symbol overlap:
#         +50 per shared identifier between the fixture filename / source
#             text and the candidate `contract` name (case-sensitive identifier
#             match, then case-insensitive fallback at half weight).
#         +20 per shared identifier with any `suggested_functions` entry.
#         +10 per shared identifier with the `angle_id` (e.g. A-RACE).
#   (b) Directory proximity ranking (only highest tier counts):
#         test/                        -> +40
#         poc-tests/                   -> +35
#         tests/integration/           -> +30
#         tests/                       -> +25
#         lib/**/test/ or lib/**/tests -> +15
#         anywhere else under workspace-> +5
#   (c) Recency: +20 if mtime is within 30 days, +10 if within 180 days,
#       0 otherwise. (Newer fixtures are more likely to compile against
#       current source.)
#   (d) Compile artifact: +25 if a sibling `out/` Foundry build artifact
#       exists for the fixture's `.t.sol` filename, else 0.
#
# Tie-breaking: by descending score, then by ascending workspace-relative
# path string so the result is reproducible across runs.

DEFAULT_FIXTURE_SEARCH_DIRS: Tuple[str, ...] = (
    "test",
    "poc-tests",
    "tests/integration",
    "tests",
    "pocs/test",
)

DEFAULT_FIXTURE_MIN_SCORE = 30


def _proximity_score(rel_path: str) -> int:
    if rel_path.startswith("test/"):
        return 40
    if rel_path.startswith("poc-tests/"):
        return 35
    if rel_path.startswith("tests/integration/"):
        return 30
    if rel_path.startswith("tests/"):
        return 25
    if rel_path.startswith("lib/") and ("/test/" in rel_path or "/tests/" in rel_path):
        return 15
    return 5


def _recency_score(mtime: float, now: Optional[float] = None) -> int:
    if mtime <= 0:
        return 0
    now = now if now is not None else time.time()
    age_days = max(0.0, (now - mtime) / 86400.0)
    if age_days <= 30:
        return 20
    if age_days <= 180:
        return 10
    return 0


def _identifier_tokens(text: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text or "")


def _shared_symbol_score(rel_path: str, source_text: str, contract: str,
                         suggested_functions: List[str], angle_id: str) -> int:
    tokens = set(_identifier_tokens(rel_path)) | set(_identifier_tokens(source_text))
    tokens_lower = {t.lower() for t in tokens}
    score = 0
    if contract:
        if contract in tokens:
            score += 50
        elif contract.lower() in tokens_lower:
            score += 25
    for func in suggested_functions or []:
        if not func:
            continue
        if func in tokens:
            score += 20
        elif func.lower() in tokens_lower:
            score += 10
    if angle_id and angle_id in tokens:
        score += 10
    return score


def _compile_artifact_score(workspace: Path, fixture_path: Path) -> int:
    out_dir = workspace / "out"
    if not out_dir.is_dir():
        return 0
    name = fixture_path.name
    artifact_dir = out_dir / name
    if artifact_dir.is_dir():
        return 25
    return 0


def _read_fixture_head(path: Path, limit: int = 4096) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def enumerate_workspace_fixtures(workspace: Path,
                                 search_dirs: Tuple[str, ...] = DEFAULT_FIXTURE_SEARCH_DIRS
                                 ) -> Tuple[List[Path], List[str]]:
    """Return (fixtures, searched_directories_relative).

    `fixtures` is sorted, deduplicated, workspace-relative-stable. The second
    element lists every directory we *attempted* to walk, so the no-match
    warning can be specific.
    """
    fixtures: List[Path] = []
    seen: set = set()
    searched: List[str] = []
    for sub in search_dirs:
        directory = workspace / sub
        searched.append(sub)
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.t.sol"):
            if not path.is_file():
                continue
            try:
                rel_str = path.relative_to(workspace).as_posix()
            except ValueError:
                rel_str = path.as_posix()
            if rel_str in seen:
                continue
            seen.add(rel_str)
            fixtures.append(path)
    fixtures.sort(key=lambda p: p.relative_to(workspace).as_posix() if p.is_absolute() else p.as_posix())
    return fixtures, searched


def score_fixture(workspace: Path, fixture_path: Path, contract: str,
                  suggested_functions: List[str], angle_id: str = "",
                  now: Optional[float] = None) -> Dict[str, Any]:
    """Score a single fixture deterministically.

    Returns a dict carrying both the total and a per-component breakdown so
    the manifest can show *why* a fixture was picked.
    """
    try:
        rel_path = fixture_path.relative_to(workspace).as_posix()
    except ValueError:
        rel_path = fixture_path.as_posix()
    head = _read_fixture_head(fixture_path)
    symbol = _shared_symbol_score(rel_path, head, contract, suggested_functions, angle_id)
    proximity = _proximity_score(rel_path)
    try:
        mtime = fixture_path.stat().st_mtime
    except OSError:
        mtime = 0.0
    recency = _recency_score(mtime, now)
    compile_pts = _compile_artifact_score(workspace, fixture_path)
    total = symbol + proximity + recency + compile_pts
    return {
        "path": rel_path,
        "score": total,
        "components": {
            "shared_symbol": symbol,
            "directory_proximity": proximity,
            "recency": recency,
            "compile_artifact": compile_pts,
        },
        "mtime": mtime,
    }


def rank_workspace_fixtures(workspace: Path, contract: str,
                            suggested_functions: List[str],
                            angle_id: str = "",
                            search_dirs: Tuple[str, ...] = DEFAULT_FIXTURE_SEARCH_DIRS,
                            now: Optional[float] = None
                            ) -> Tuple[List[Dict[str, Any]], List[str]]:
    fixtures, searched = enumerate_workspace_fixtures(workspace, search_dirs)
    scored = [
        score_fixture(workspace, f, contract, suggested_functions, angle_id, now=now)
        for f in fixtures
    ]
    # Deterministic sort: highest score first, then by path.
    scored.sort(key=lambda entry: (-entry["score"], entry["path"]))
    return scored, searched


def write_fixture_selection_manifest(workspace: Path,
                                     manifest: Dict[str, Any]) -> Path:
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_path = out_dir / f"poc_fixture_selection_{ts}.json"
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    return out_path


def select_best_fixture(workspace: Optional[Path], contract: str,
                        suggested_functions: List[str], angle_id: str = "",
                        min_score: int = DEFAULT_FIXTURE_MIN_SCORE,
                        search_dirs: Tuple[str, ...] = DEFAULT_FIXTURE_SEARCH_DIRS,
                        write_manifest: bool = True,
                        require_fixture: bool = False,
                        now: Optional[float] = None
                        ) -> Dict[str, Any]:
    """Enumerate, score, and pick the best workspace fixture.

    Returns a manifest dict (also written under
    `<workspace>/.auditooor/poc_fixture_selection_<ts>.json` when
    `write_manifest=True`).

    When no fixture exists or the highest-scoring one is below `min_score`,
    the manifest carries `selected: null`, an explicit `warning`, and the
    list of `searched_directories`. If `require_fixture=True` and nothing
    meets the threshold, raises ValueError.
    """
    manifest: Dict[str, Any] = {
        "schema": "poc_fixture_selection.v1",
        "contract": contract,
        "angle_id": angle_id,
        "suggested_functions": list(suggested_functions or []),
        "min_score": min_score,
        "workspace": str(workspace) if workspace else None,
        "searched_directories": [],
        "ranking": [],
        "selected": None,
        "reason": "",
        "warning": "",
        "manifest_path": None,
    }
    if workspace is None:
        manifest["reason"] = "no workspace supplied"
        manifest["warning"] = "fixture-scoring skipped: no workspace path was provided to poc-scaffold"
        if require_fixture:
            raise ValueError(manifest["warning"])
        return manifest

    ranking, searched = rank_workspace_fixtures(
        workspace, contract, suggested_functions, angle_id,
        search_dirs=search_dirs, now=now,
    )
    manifest["searched_directories"] = list(searched)
    manifest["ranking"] = ranking

    if not ranking:
        warning = (
            "no project test fixtures found; falling back to generic scaffold. "
            f"searched directories under {workspace.as_posix()}: "
            + ", ".join(searched if searched else ["(none)"])
            + ". reason: no `*.t.sol` files were discovered in any of these directories."
        )
        manifest["reason"] = "no fixtures discovered"
        manifest["warning"] = warning
        if require_fixture:
            raise ValueError(warning)
        if write_manifest:
            try:
                manifest["manifest_path"] = str(
                    write_fixture_selection_manifest(workspace, manifest)
                )
            except OSError as exc:  # pragma: no cover - manifest IO is best-effort
                manifest["warning"] += f" (manifest write failed: {exc})"
        return manifest

    best = ranking[0]
    if best["score"] < min_score:
        warning = (
            f"best workspace fixture `{best['path']}` scored {best['score']} "
            f"below threshold {min_score}; falling back to generic scaffold. "
            f"searched directories: {', '.join(searched)}. "
            "reason: shared-symbol overlap and directory proximity were too low to "
            "trust the fixture for this contract/angle pair."
        )
        manifest["reason"] = "below minimum score"
        manifest["warning"] = warning
        if require_fixture:
            raise ValueError(warning)
        if write_manifest:
            try:
                manifest["manifest_path"] = str(
                    write_fixture_selection_manifest(workspace, manifest)
                )
            except OSError as exc:  # pragma: no cover
                manifest["warning"] += f" (manifest write failed: {exc})"
        return manifest

    manifest["selected"] = best
    manifest["reason"] = (
        f"highest-scoring fixture (score={best['score']}, "
        f"shared_symbol={best['components']['shared_symbol']}, "
        f"directory_proximity={best['components']['directory_proximity']}, "
        f"recency={best['components']['recency']}, "
        f"compile_artifact={best['components']['compile_artifact']}) "
        "above minimum threshold."
    )
    if write_manifest:
        try:
            manifest["manifest_path"] = str(
                write_fixture_selection_manifest(workspace, manifest)
            )
        except OSError as exc:  # pragma: no cover
            manifest["warning"] = f"manifest write failed: {exc}"
    return manifest


def existing_fixture_hints(workspace: Optional[Path], contract: str, suggested_functions: List[str]) -> List[str]:
    hints: List[str] = []
    if contract == "NegRiskAdapter":
        hints.append(
            "start from src/v1/neg-risk/snapshots/NegRiskAdapter.snap.sol for prepareMarket/prepareQuestion setup"
        )
        hints.extend(neg_risk_fixture_hints(workspace, suggested_functions))
    if "resolveQuestion" in suggested_functions:
        hints.append(
            "reuse NegRiskOperator flow expectations from src/v1/neg-risk/NegRiskOperator.sol around reportPayouts/resolveQuestion"
        )
    if workspace is not None and contract == "NegRiskAdapter":
        candidate_paths = [
            workspace / "lib/neg-risk-ctf-adapter/src/test/Integration.t.sol",
            workspace / "pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol",
            workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskOperator.t.sol",
            workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/PrepareMarket.t.sol",
            workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/PrepareQuestion.t.sol",
        ]
        for path in candidate_paths:
            if path.exists():
                try:
                    rel = path.relative_to(workspace)
                except ValueError:
                    rel = path
                hints.append(f"workspace fixture available: {rel.as_posix()}")
    return hints


def neg_risk_fixture_hints(workspace: Optional[Path], suggested_functions: List[str]) -> List[str]:
    if workspace is None:
        return []

    hints: List[str] = []
    integration = workspace / "lib/neg-risk-ctf-adapter/src/test/Integration.t.sol"
    convert_positions = workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/ConvertPositions.t.sol"
    report_outcome = workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/ReportOutcome.t.sol"

    if integration.exists():
        hints.append(
            "primary base: extend lib/neg-risk-ctf-adapter/src/test/Integration.t.sol::IntegrationTest.test_initializePrepareAndResolve for real prepare/initialize/resolve interleavings"
        )
    unflag_race = workspace / "pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol"
    if unflag_race.exists():
        hints.append(
            "secondary base: reuse pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol for proven unflag/emergency-resolution assertions"
        )
    if convert_positions.exists():
        hints.append(
            "reuse lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/ConvertPositions.t.sol::NegRiskAdapter_ConvertPositions_Test._before/_after and test_convertPositions for market seeding and post-state checks"
        )
    if "reportOutcome" in suggested_functions and report_outcome.exists():
        hints.append(
            "if outcome reporting is part of the path, borrow lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/ReportOutcome.t.sol::NegRiskAdapter_ReportOutcome_Test.setUp/test_reportOutcome"
        )
    return hints


def build_interleaving_steps(contract: str, angle_id: str, suggested_functions: List[str],
                             workspace: Optional[Path] = None) -> List[str]:
    steps: List[str] = []
    if angle_id == "A-RACE" and suggested_functions:
        steps.extend(neg_risk_fixture_hints(workspace, suggested_functions))
        steps.append("pin the fork block and prove the paired live topology rows before the exploit path")
        if "prepareMarket" in suggested_functions:
            steps.append(f"call {contract}.prepareMarket or the upstream operator wrapper to create the market state")
        if "prepareQuestion" in suggested_functions:
            steps.append("capture the returned marketId / requestId mapping before the second write")
            steps.append(f"interleave {contract}.prepareQuestion through the live operator->adapter edge")
        if "resolveQuestion" in suggested_functions:
            steps.append("attempt resolveQuestion before and after the second state transition to probe desync")
            steps.append("assert unexpected success/revert or mismatched state derived from stale question/market linkage")
    if not steps and suggested_functions:
        for func in suggested_functions:
            steps.append(f"drive a candidate transaction around `{func}` and assert the hypothesis from the exploit goal")
    return steps


def render_actor_lines(contract: str, angle_id: str, suggested_functions: List[str],
                       use_neg_risk_adapter_fixture: bool = False,
                       use_neg_risk_integration_fixture: bool = False) -> str:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            lines = ["    // Suggested actor roles for the NegRisk integration interleaving path"]
            return "\n".join(lines)
        if use_neg_risk_adapter_fixture:
            lines = [
                "    // Suggested actor roles for the NegRisk interleaving path",
                "    address internal attacker;",
                "    bytes32 internal requestId = bytes32(uint256(0xA11CE));",
            ]
            return "\n".join(lines)
        lines = [
            "    // Suggested actor roles for the NegRisk interleaving path",
            "    address internal admin = makeAddr(\"admin\");",
            "    address internal oracle = makeAddr(\"oracle\");",
            "    address internal attacker = makeAddr(\"attacker\");",
            "    bytes32 internal requestId = bytes32(uint256(0xA11CE));",
        ]
        return "\n".join(lines)
    return ""


def should_use_real_neg_risk_operator(workspace: Optional[Path], contract: str, angle_id: str,
                                      suggested_functions: List[str],
                                      use_neg_risk_adapter_fixture: bool = False) -> bool:
    if workspace is None:
        return False
    if contract != "NegRiskAdapter" or angle_id != "A-RACE" or "resolveQuestion" not in suggested_functions:
        return False
    if use_neg_risk_adapter_fixture:
        return False
    return (workspace / "src/v1/neg-risk/NegRiskOperator.sol").exists()


def should_use_neg_risk_adapter_fixture(workspace: Optional[Path], contract: str, angle_id: str,
                                        suggested_functions: List[str]) -> bool:
    if workspace is None:
        return False
    if contract != "NegRiskAdapter" or angle_id != "A-RACE":
        return False
    required = {"prepareMarket", "prepareQuestion", "resolveQuestion"}
    if not required.issubset(set(suggested_functions)):
        return False
    return (workspace / "lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/NegRiskAdapterSetUp.sol").exists()


def should_use_neg_risk_integration_fixture(workspace: Optional[Path], contract: str, angle_id: str,
                                            suggested_functions: List[str]) -> bool:
    if workspace is None:
        return False
    if contract != "NegRiskAdapter" or angle_id != "A-RACE":
        return False
    required = {"prepareMarket", "prepareQuestion", "resolveQuestion"}
    if not required.issubset(set(suggested_functions)):
        return False
    return (workspace / "lib/neg-risk-ctf-adapter/src/test/Integration.t.sol").exists()


def render_extra_imports(contract: str, angle_id: str, suggested_functions: List[str],
                         use_real_neg_risk_operator: bool,
                         use_neg_risk_adapter_fixture: bool = False,
                         use_neg_risk_integration_fixture: bool = False) -> str:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            return '\nimport {IntegrationTest} from "src/test/Integration.t.sol";\n'
        if use_neg_risk_adapter_fixture:
            return (
                '\nimport {NegRiskAdapter_SetUp} from "src/test/NegRiskAdapter/NegRiskAdapterSetUp.sol";\n'
                'import {NegRiskIdLib} from "src/libraries/NegRiskIdLib.sol";\n'
                'import {NegRiskOperator} from "src/NegRiskOperator.sol";\n'
            )
        if use_real_neg_risk_operator:
            return '\nimport {NegRiskOperator} from "src/NegRiskOperator.sol";\n'
        return ""
    return ""


def render_state_var_lines(contract: str, angle_id: str, suggested_functions: List[str],
                           use_real_neg_risk_operator: bool = False,
                           use_neg_risk_adapter_fixture: bool = False,
                           use_neg_risk_integration_fixture: bool = False) -> str:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            lines = [
                "    address internal attacker;",
                "    bytes32 internal marketId;",
                "    bytes32 internal questionId;",
                "    bytes32 internal requestId;",
            ]
            return "\n".join(lines)
        if use_neg_risk_adapter_fixture:
            lines = [
                "    NegRiskOperator internal nrOperator;",
                "    bytes32 internal marketId;",
                "    bytes32 internal questionId;",
                "    uint256[] internal payoutsTrue;",
                "    uint256[] internal payoutsFalse;",
            ]
            return "\n".join(lines)
        operator_binding = "NegRiskOperator" if use_real_neg_risk_operator else "INegRiskOperatorHarness"
        lines = [
            f"    {operator_binding} internal nrOperator;",
            "    MockNegRiskAdapter internal adapter;",
            "    bytes32 internal questionId;",
            "    uint256[] internal payoutsTrue;",
            "    uint256[] internal payoutsFalse;",
        ]
        return "\n".join(lines)
    return ""


def render_support_contracts(contract: str, angle_id: str, suggested_functions: List[str],
                             use_real_neg_risk_operator: bool = False,
                             use_neg_risk_adapter_fixture: bool = False,
                             use_neg_risk_integration_fixture: bool = False) -> str:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            return ""
        if use_neg_risk_adapter_fixture:
            return ""
        interface_block = ""
        if not use_real_neg_risk_operator:
            interface_block = """interface INegRiskOperatorHarness {
    function setOracle(address _oracle) external;
    function reportPayouts(bytes32 _requestId, uint256[] calldata _payouts) external;
    function flagQuestion(bytes32 _questionId) external;
    function unflagQuestion(bytes32 _questionId) external;
    function resolveQuestion(bytes32 _questionId) external;
    function emergencyResolveQuestion(bytes32 _questionId, bool _result) external;
    function questionIds(bytes32 _requestId) external view returns (bytes32);
    function flaggedAt(bytes32 _questionId) external view returns (uint256);
}
"""

        return """{interface_block}
contract MockNegRiskAdapter {
    struct Report { bytes32 questionId; bool outcome; bool exists; }

    mapping(bytes32 => Report) public reports;

    error AlreadyReported();

    function reportOutcome(bytes32 _questionId, bool _outcome) external {
        if (reports[_questionId].exists) revert AlreadyReported();
        reports[_questionId] = Report({ questionId: _questionId, outcome: _outcome, exists: true });
    }

    function isReported(bytes32 _questionId) external view returns (bool) {
        return reports[_questionId].exists;
    }
}
""".replace("{interface_block}", interface_block)
    return ""


def render_helper_lines(contract: str, angle_id: str, suggested_functions: List[str],
                        use_real_neg_risk_operator: bool = False,
                        use_neg_risk_adapter_fixture: bool = False,
                        use_neg_risk_integration_fixture: bool = False) -> str:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            return """    function _initResolutionOnlyHarness() internal {
        super.setUp();
        attacker = brian;
    }

    function _seedPreparedQuestion() internal {
        bytes memory data = new bytes(100);
        uint256 reward = 1_000_000;
        uint256 proposalBond = 5_000_000;
        uint256 liveness = 100;

        vm.prank(admin);
        marketId = nrOperator.prepareMarket(0, data);

        vm.startPrank(brian);
        usdc.mint(brian, reward);
        usdc.approve(address(umaCtfAdapter), reward);
        requestId = umaCtfAdapter.initialize(data, address(usdc), reward, proposalBond, liveness);
        vm.stopPrank();

        vm.prank(admin);
        nrOperator.prepareQuestion(marketId, data, bytes32(0));

        vm.prank(admin);
        questionId = nrOperator.prepareQuestion(marketId, data, requestId);
    }

    function _runIntegrationResolvePath(bool reportedResult) internal {
        _seedPreparedQuestion();

        optimisticOracle.setPrice(reportedResult ? int256(1 ether) : int256(0));
        umaCtfAdapter.resolve(requestId);

        skip(nrOperator.DELAY_PERIOD());

        vm.prank(attacker);
        nrOperator.resolveQuestion(questionId);
    }

    function _assertCommittedOutcome(bool expectedOutcome) internal view {
        assertTrue(nrAdapter.getDetermined(marketId), "market determined");
        assertEq(nrAdapter.getResult(marketId), expectedOutcome ? 1 : 0, "market result mismatch");
    }

    function _assertAdminCorrectionTooLate(bool correctedOutcome) internal pure {
        correctedOutcome;
        // TODO: extend with a distinct admin-correction or second-write path if the
        // fresh interleaving variant proves one. The base IntegrationTest path does
        // not model the submitted unflag race directly.
    }"""
        if use_neg_risk_adapter_fixture:
            return """    function _seedNegRiskQuestion() internal returns (bytes32 seededMarketId, bytes32 seededQuestionId) {
        vm.prank(admin);
        seededMarketId = nrOperator.prepareMarket(0, bytes("market"));

        vm.prank(admin);
        seededQuestionId = nrOperator.prepareQuestion(seededMarketId, bytes("question"), requestId);

        assertEq(nrOperator.questionIds(requestId), seededQuestionId, "requestId mapping seeded");
    }

    function _initResolutionOnlyHarness() internal {
        super.setUp();
        attacker = brian;

        payoutsTrue = new uint256[](2);
        payoutsTrue[0] = 1;
        payoutsTrue[1] = 0;

        payoutsFalse = new uint256[](2);
        payoutsFalse[0] = 0;
        payoutsFalse[1] = 1;

        vm.prank(admin);
        nrOperator = new NegRiskOperator(address(nrAdapter));

        vm.prank(admin);
        nrOperator.setOracle(oracle);

        (marketId, questionId) = _seedNegRiskQuestion();
    }

    function _wireResolutionOnlyOperator(address operator) internal {
        nrOperator = NegRiskOperator(operator);
    }

    function _seedQuestionIdBackdoor(address operator, bytes32 requestId_, bytes32 questionId_) internal pure {
        operator; requestId_; questionId_;
        revert("fixture mode uses real prepareQuestion");
    }

    function _openResolveWindow(bytes32 activeQuestionId, bool reportedResult) internal {
        uint256[] memory payouts = reportedResult ? payoutsTrue : payoutsFalse;

        vm.prank(oracle);
        nrOperator.reportPayouts(requestId, payouts);

        vm.prank(admin);
        nrOperator.flagQuestion(activeQuestionId);

        vm.prank(admin);
        nrOperator.unflagQuestion(activeQuestionId);
        assertEq(nrOperator.flaggedAt(activeQuestionId), 0, "unflagged");
    }

    function _runUnflagRace(bool reportedResult) internal {
        require(address(nrOperator) != address(0), "wire operator");
        _openResolveWindow(questionId, reportedResult);

        vm.prank(attacker);
        nrOperator.resolveQuestion(questionId);
    }

    function _assertCommittedOutcome(bool expectedOutcome) internal view {
        bytes32 conditionId = nrAdapter.getConditionId(questionId);
        assertEq(ctf.payoutDenominator(conditionId), 1, "condition resolved");
        assertEq(ctf.payoutNumerators(conditionId, 0), expectedOutcome ? 1 : 0, "slot0 outcome mismatch");
        assertEq(ctf.payoutNumerators(conditionId, 1), expectedOutcome ? 0 : 1, "slot1 outcome mismatch");
    }

    function _assertAdminCorrectionTooLate(bool correctedOutcome) internal {
        vm.prank(admin);
        vm.expectRevert();
        nrOperator.emergencyResolveQuestion(questionId, correctedOutcome);
    }"""
        if use_real_neg_risk_operator:
            return """    function _seedNegRiskQuestion() internal returns (bytes32 marketId, bytes32 questionId) {
        // TODO: bootstrap from NegRiskOperator.t.sol or NegRiskAdapterSetUp.sol
        // vm.prank(admin);
        // marketId = nrOperator.prepareMarket(0, bytes("market"));
        // vm.prank(admin);
        // questionId = nrOperator.prepareQuestion(marketId, bytes("question"), requestId);
    }

    function _initResolutionOnlyHarness() internal {
        adapter = new MockNegRiskAdapter();
        questionId = bytes32(uint256(0xDEADBEEF));

        payoutsTrue = new uint256[](2);
        payoutsTrue[0] = 1;
        payoutsTrue[1] = 0;

        payoutsFalse = new uint256[](2);
        payoutsFalse[0] = 0;
        payoutsFalse[1] = 1;

        nrOperator = new NegRiskOperator(address(adapter));
        nrOperator.setOracle(oracle);
        _seedQuestionIdBackdoor(address(nrOperator), requestId, questionId);
    }

    function _wireResolutionOnlyOperator(address operator) internal {
        nrOperator = NegRiskOperator(operator);
        // TODO: if you deploy a fresh operator in this harness, also call:
        // nrOperator.setOracle(oracle);
        // _seedQuestionIdBackdoor(operator, requestId, questionId);
    }

    function _seedQuestionIdBackdoor(address operator, bytes32 requestId_, bytes32 questionId_) internal {
        // Baseline trick from pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol:
        // if the adapter side is too heavy to model, seed questionIds[requestId] directly.
        // NegRiskOperator layout in that PoC:
        //   slot 0 = admins mapping
        //   slot 1 = oracle
        //   slot 2 = questionIds mapping
        // bytes32 slot = keccak256(abi.encode(requestId_, uint256(2)));
        // vm.store(operator, slot, questionId_);
        // assertEq(nrOperator.questionIds(requestId_), questionId_, "questionId mapping write succeeded");
    }

    function _openResolveWindow(bytes32 questionId, bool reportedResult) internal {
        // TODO: model the exact unflag race window:
        // uint256[] memory payouts = new uint256[](2);
        // payouts[0] = reportedResult ? 1 : 0;
        // payouts[1] = reportedResult ? 0 : 1;
        // 1. vm.prank(oracle); nrOperator.reportPayouts(requestId, payouts);
        // 2. vm.prank(admin); nrOperator.flagQuestion(questionId);
        // 3. vm.prank(admin); nrOperator.unflagQuestion(questionId);
        // 4. vm.prank(attacker); nrOperator.resolveQuestion(questionId);
        // 5. assertEq(nrOperator.flaggedAt(questionId), 0, "unflagged");
    }

    function _runUnflagRace(bool reportedResult) internal {
        require(address(nrOperator) != address(0), "wire operator");
        uint256[] memory payouts = reportedResult ? payoutsTrue : payoutsFalse;

        vm.prank(oracle);
        nrOperator.reportPayouts(requestId, payouts);

        vm.prank(admin);
        nrOperator.flagQuestion(questionId);

        vm.prank(admin);
        nrOperator.unflagQuestion(questionId);
        assertEq(nrOperator.flaggedAt(questionId), 0, "unflagged");

        vm.prank(attacker);
        nrOperator.resolveQuestion(questionId);
    }

    function _assertCommittedOutcome(bool expectedOutcome) internal view {
        assertTrue(adapter.isReported(questionId), "outcome committed to adapter");
        (, bool outcome,) = adapter.reports(questionId);
        assertEq(outcome, expectedOutcome, "committed outcome mismatch");
    }

    function _assertAdminCorrectionTooLate(bool correctedOutcome) internal {
        vm.prank(admin);
        vm.expectRevert();
        nrOperator.emergencyResolveQuestion(questionId, correctedOutcome);
    }"""
        return """    function _seedNegRiskQuestion() internal returns (bytes32 marketId, bytes32 questionId) {
        // TODO: bootstrap from NegRiskOperator.t.sol or NegRiskAdapterSetUp.sol
        // vm.prank(admin);
        // marketId = nrOperator.prepareMarket(0, bytes("market"));
        // vm.prank(admin);
        // questionId = nrOperator.prepareQuestion(marketId, bytes("question"), requestId);
    }

    function _initResolutionOnlyHarness() internal {
        adapter = new MockNegRiskAdapter();
        questionId = bytes32(uint256(0xDEADBEEF));

        payoutsTrue = new uint256[](2);
        payoutsTrue[0] = 1;
        payoutsTrue[1] = 0;

        payoutsFalse = new uint256[](2);
        payoutsFalse[0] = 0;
        payoutsFalse[1] = 1;

        // TODO: once imports are enabled, wire the real operator:
        // nrOperator = new NegRiskOperator(address(adapter));
        // nrOperator.setOracle(oracle);
        // _seedQuestionIdBackdoor(address(nrOperator), requestId, questionId);
    }

    function _wireResolutionOnlyOperator(address operator) internal {
        nrOperator = INegRiskOperatorHarness(operator);
        // TODO: if you deploy a fresh operator in this harness, also call:
        // nrOperator.setOracle(oracle);
        // _seedQuestionIdBackdoor(operator, requestId, questionId);
    }

    function _seedQuestionIdBackdoor(address operator, bytes32 requestId_, bytes32 questionId_) internal {
        // Baseline trick from pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol:
        // if the adapter side is too heavy to model, seed questionIds[requestId] directly.
        // NegRiskOperator layout in that PoC:
        //   slot 0 = admins mapping
        //   slot 1 = oracle
        //   slot 2 = questionIds mapping
        // bytes32 slot = keccak256(abi.encode(requestId_, uint256(2)));
        // vm.store(operator, slot, questionId_);
        // assertEq(nrOperator.questionIds(requestId_), questionId_, "questionId mapping write succeeded");
    }

    function _openResolveWindow(bytes32 questionId, bool reportedResult) internal {
        // TODO: model the exact unflag race window:
        // uint256[] memory payouts = new uint256[](2);
        // payouts[0] = reportedResult ? 1 : 0;
        // payouts[1] = reportedResult ? 0 : 1;
        // 1. vm.prank(oracle); nrOperator.reportPayouts(requestId, payouts);
        // 2. vm.prank(admin); nrOperator.flagQuestion(questionId);
        // 3. vm.prank(admin); nrOperator.unflagQuestion(questionId);
        // 4. vm.prank(attacker); nrOperator.resolveQuestion(questionId);
        // 5. assertEq(nrOperator.flaggedAt(questionId), 0, "unflagged");
        // Optional resolution-only harness:
        //  - deploy a MockNegRiskAdapter that records reportOutcome(questionId, outcome)
        //  - deploy NegRiskOperator(address(mockAdapter))
        //  - setOracle(oracle)
        //  - use _seedQuestionIdBackdoor(...) if you only need operator-side race semantics
    }

    function _runUnflagRace(bool reportedResult) internal {
        require(address(nrOperator) != address(0), "wire operator");
        uint256[] memory payouts = reportedResult ? payoutsTrue : payoutsFalse;

        vm.prank(oracle);
        nrOperator.reportPayouts(requestId, payouts);

        vm.prank(admin);
        nrOperator.flagQuestion(questionId);

        vm.prank(admin);
        nrOperator.unflagQuestion(questionId);
        assertEq(nrOperator.flaggedAt(questionId), 0, "unflagged");

        vm.prank(attacker);
        nrOperator.resolveQuestion(questionId);
    }

    function _assertCommittedOutcome(bool expectedOutcome) internal view {
        assertTrue(adapter.isReported(questionId), "outcome committed to adapter");
        (, bool outcome,) = adapter.reports(questionId);
        assertEq(outcome, expectedOutcome, "committed outcome mismatch");
    }

    function _assertAdminCorrectionTooLate(bool correctedOutcome) internal {
        vm.prank(admin);
        vm.expectRevert();
        nrOperator.emergencyResolveQuestion(questionId, correctedOutcome);
    }"""
    return ""


def render_assertion_lines(contract: str, angle_id: str, suggested_functions: List[str]) -> List[str]:
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        return [
            "Baseline once wired: _runUnflagRace(true); _assertCommittedOutcome(true); _assertAdminCorrectionTooLate(false);",
            "TODO: mirror lib/neg-risk-ctf-adapter/src/test/Integration.t.sol::IntegrationTest.test_initializePrepareAndResolve so the timing chain matches the live operator/oracle sequence",
            "TODO: reuse lib/neg-risk-ctf-adapter/src/test/NegRiskAdapter/ConvertPositions.t.sol::NegRiskAdapter_ConvertPositions_Test._after to assert brian balances, burn-address balances, vault fees, and wcol balance after the race",
            "TODO: assert the attacker can resolve in the reopened window after unflagQuestion",
            "TODO: assert the downstream adapter / CTF state reflects the first committed outcome (e.g. reportOutcome/CTF payout recorded)",
            "TODO: assert an admin correction path now reverts or becomes too late, mirroring the unflag-race baseline PoC",
        ]
    return []


def render_baseline_execution_lines(contract: str, angle_id: str, suggested_functions: List[str],
                                    use_neg_risk_adapter_fixture: bool = False,
                                    use_neg_risk_integration_fixture: bool = False) -> str:
    lines: List[str] = []
    if contract == "NegRiskAdapter" and angle_id == "A-RACE" and "resolveQuestion" in suggested_functions:
        if use_neg_risk_integration_fixture:
            lines = [
                "_runIntegrationResolvePath(true);",
                "_assertCommittedOutcome(true);",
                "_assertAdminCorrectionTooLate(false);",
            ]
        else:
            lines = [
                "_runUnflagRace(true);",
                "_assertCommittedOutcome(true);",
                "_assertAdminCorrectionTooLate(false);",
            ]
    if not lines:
        lines = ["// TODO: add the strongest baseline execution path for this seam"]
    return "\n".join(f"        {line}" for line in lines)


def infer_workspace_from_plan_json(plan_json: Path) -> Optional[Path]:
    if plan_json.parent.name == "swarm":
        return plan_json.parent.parent
    return None


def find_contract_source(workspace: Path, contract: str) -> Optional[Path]:
    exact = sorted(workspace.rglob(f"{contract}.sol"))
    if exact:
        preferred = sorted(
            exact,
            key=lambda path: (
                0 if "/src/" in path.as_posix() else 1,
                len(path.as_posix()),
            ),
        )
        return preferred[0]
    return None


def emit_composition_contracts(workspace: Path, candidate: Dict[str, Any], out_path: Path) -> Optional[Path]:
    involved = candidate.get("involved_contracts", [])
    if len(involved) < 2:
        return None

    entries: List[str] = []
    for contract in involved:
        source = find_contract_source(workspace, contract)
        if source is None:
            continue
        try:
            rel = source.relative_to(workspace)
        except ValueError:
            rel = source
        entries.append(f"{contract}:{rel.as_posix()}")

    if len(entries) < 2:
        return None

    contract_list = out_path.with_suffix(out_path.suffix + ".contracts.txt")
    contract_list.write_text("\n".join(entries) + "\n")
    return contract_list


def maybe_generate_composition_fuzz(workspace: Path, candidate: Dict[str, Any], out_path: Path) -> Optional[Path]:
    contract_list = emit_composition_contracts(workspace, candidate, out_path)
    if contract_list is None or not GEN_COMPOSITION_FUZZ.exists():
        return None
    result = subprocess.run(
        ["bash", str(GEN_COMPOSITION_FUZZ), str(workspace), str(contract_list)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[scaffold] WARN: composition fuzz generation failed: {result.stderr.strip()}", file=sys.stderr)
        return None
    match = re.search(r"\[info\] done: (.+)", result.stdout)
    if match:
        return Path(match.group(1).strip())
    return None


def write_evidence_class_sidecar(out_path: Path, *,
                                 candidate: Optional[Dict[str, Any]],
                                 pattern: Optional[str],
                                 target_contract: str,
                                 target_func: str) -> Path:
    """Write a sidecar JSON next to ``out_path`` declaring the scaffold's
    ``evidence_class`` (item #14).

    A scaffold is always at most ``scaffolded_unverified`` until
    ``poc-execution-record.py`` writes an execution manifest. The sidecar
    captures the upstream candidate's ``evidence_class`` (if any) so we
    can WARN when a brief candidate was missing the field — a legacy row
    should not silently become ``scaffolded_unverified``.
    """
    sidecar = out_path.with_name(out_path.name + ".evidence_class.json")
    upstream_class: Optional[str] = None
    upstream_legacy = False
    if isinstance(candidate, dict):
        raw = candidate.get("evidence_class")
        if _evidence_class.is_known(raw):
            upstream_class = str(raw)
        elif raw is None:
            upstream_legacy = True
    payload = {
        "schema_version": _evidence_class.SCHEMA_VERSION,
        "evidence_class": _evidence_class.SCAFFOLDED_UNVERIFIED,
        "scaffold_path": str(out_path),
        "pattern_id": pattern or "",
        "target_contract": target_contract,
        "target_function": target_func,
        "upstream_candidate_evidence_class": upstream_class,
        "upstream_candidate_legacy": upstream_legacy,
        "note": (
            "scaffold-only output; raise to executed_with_manifest only via "
            "tools/poc-execution-record.py"
        ),
    }
    sidecar.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return sidecar


def main() -> None:
    parser = argparse.ArgumentParser(description="PoC scaffold generator")
    parser.add_argument("--pattern", help="CCIA pattern ID (e.g., A-REENT)")
    parser.add_argument("--contract", help="Target contract name")
    parser.add_argument("--func", help="Target function name (optional)")
    parser.add_argument("--contract-path", help="Import path for contract (optional)")
    parser.add_argument("--plan-json", help="Candidate plan JSON from agent-output-synthesizer --brief-candidates")
    parser.add_argument("--angle-id", help="Angle ID selector for --plan-json")
    parser.add_argument("--candidate-index", type=int, help="Candidate index selector for --plan-json")
    parser.add_argument("--with-composition-fuzz", action="store_true",
                        help="When using --plan-json, also generate a composition_fuzz harness if multiple contracts are involved")
    parser.add_argument("--bootstrap-workspace",
                        help="Optional workspace to scan for reusable PoC/test fixtures when using --plan-json")
    parser.add_argument("--require-fixture", action="store_true",
                        help="Fail closed if no workspace fixture meets the minimum score (P1-5).")
    parser.add_argument("--fixture-min-score", type=int, default=DEFAULT_FIXTURE_MIN_SCORE,
                        help=("Minimum total score for a workspace fixture to be selected "
                              f"(default: {DEFAULT_FIXTURE_MIN_SCORE})."))
    parser.add_argument("--out", required=True, help="Output .t.sol file path")
    args = parser.parse_args()

    selection_meta: Optional[Dict[str, Any]] = None
    candidate: Optional[Dict[str, Any]] = None
    plan_json: Optional[Path] = None
    try:
        if args.plan_json:
            plan_json = Path(args.plan_json)
            candidate, selection_meta = load_candidate_plan(
                plan_json,
                args.contract,
                args.angle_id,
                args.candidate_index,
            )
            blockers = scaffold_blockers(candidate)
            if blockers:
                raise ValueError(
                    "Refusing to scaffold blocked candidate:\n- "
                    + "\n- ".join(blockers)
                )
            workspace = infer_workspace_from_plan_json(plan_json)
            require_locked_impact_contract(candidate, workspace)
            bootstrap_workspace = (
                Path(args.bootstrap_workspace).expanduser().resolve()
                if args.bootstrap_workspace else workspace
            )
            fixture_selection = select_best_fixture(
                bootstrap_workspace,
                candidate.get("contract", ""),
                candidate.get("suggested_functions", []) or [],
                angle_id=candidate.get("angle_id", ""),
                min_score=args.fixture_min_score,
                require_fixture=args.require_fixture,
            )
            if fixture_selection.get("warning"):
                print(f"[scaffold] {fixture_selection['warning']}", file=sys.stderr)
            if fixture_selection.get("manifest_path"):
                print(f"[scaffold] fixture-selection manifest: "
                      f"{fixture_selection['manifest_path']}")
            code = generate_plan_scaffold(candidate, bootstrap_workspace,
                                          fixture_selection=fixture_selection)
            target_contract = candidate["contract"]
            target_func = candidate["angle_id"]
            scaffold_label = "candidate-plan"
        else:
            if not args.pattern or not args.contract:
                parser.error("--pattern and --contract are required unless --plan-json is used")
            code = generate_scaffold(args.pattern, args.contract, args.func, args.contract_path)
            target_contract = args.contract
            target_func = args.func or "vulnerableFunction"
            scaffold_label = args.pattern
            workspace = None
    except ValueError as e:
        print(f"[scaffold] Error: {e}")
        sys.exit(1)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(code)

    sidecar_candidate = candidate if args.plan_json else None
    sidecar = write_evidence_class_sidecar(
        out_path,
        candidate=sidecar_candidate,
        pattern=args.pattern,
        target_contract=target_contract,
        target_func=target_func,
    )

    print(f"[scaffold] Generated {scaffold_label} PoC scaffold: {out_path}")
    print(f"[scaffold] Target: {target_contract}.{target_func}")
    print(f"[scaffold] Evidence class sidecar: {sidecar} (scaffolded_unverified)")
    if args.plan_json and isinstance(candidate, dict) and not _evidence_class.is_known(candidate.get("evidence_class")):
        print(
            "[scaffold] WARN: upstream candidate has no evidence_class; "
            "treating as legacy. Re-run agent-output-synthesizer to backfill.",
            file=sys.stderr,
        )
    if (
        args.plan_json
        and selection_meta is not None
        and selection_meta.get("ambiguity_resolved")
        and candidate is not None
        and plan_json is not None
    ):
        log_root = _ambiguity_log_root(workspace, plan_json, out_path)
        log_path = write_ambiguity_resolution_log(
            log_root, plan_json, out_path, candidate, selection_meta
        )
        alt_count = len(selection_meta.get("alternatives") or [])
        print(
            f"[scaffold] WARN: ambiguous --plan-json selection resolved via "
            f"--candidate-index {selection_meta.get('selected_index')}; "
            f"{alt_count} alternative candidate(s) were rejected"
        )
        print(f"[scaffold] WARN: ambiguity resolution logged to {log_path}")
        print(
            "[scaffold] WARN: review this log before treating the scaffold as the "
            "intended hypothesis (closeout will warn while entries remain)"
        )
    if args.plan_json and args.with_composition_fuzz and workspace is not None:
        companion = maybe_generate_composition_fuzz(workspace, candidate, out_path)
        if companion is not None:
            print(f"[scaffold] Composition fuzz harness: {companion}")
    print(f"[scaffold] Next steps:")
    print(f"  1. Replace TODO comments with actual project imports/addresses")
    print(f"  2. Fill in the attack sequence")
    print(f"  3. Run: forge test --match-path '*{out_path.name}*'")


if __name__ == "__main__":
    main()
