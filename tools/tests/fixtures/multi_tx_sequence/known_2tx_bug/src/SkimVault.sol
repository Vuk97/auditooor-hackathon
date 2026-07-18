// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Fixture for W5-D3 multi-tx attack-sequence lift.
//
// Known 2-tx bug (setup then exploit):
//   tx1 (setup):   deposit()  - attacker primes a credited balance.
//   tx2 (trigger): skim()     - skim() pays out `credited[msg.sender]` but
//                               forgets to ZERO it, so a SECOND skim() (or
//                               a withdraw) double-spends. The single-call
//                               state is fine; only the SEQUENCE breaks the
//                               solvency invariant.
//
// A single-function counterexample search cannot find this: deposit() alone
// is sound and skim() alone reverts on a zero balance. The bug only exists
// across the deposit -> skim -> skim sequence. This is exactly the class
// W5-D3 lifts into a runnable multi-tx PoC.
contract SkimVault {
    mapping(address => uint256) public credited;
    uint256 public totalCredited;

    function deposit() external payable {
        credited[msg.sender] += msg.value;
        totalCredited += msg.value;
    }

    function skim() external {
        uint256 amount = credited[msg.sender];
        require(amount > 0, "nothing to skim");
        // BUG: pays out but never zeroes `credited[msg.sender]`, so the
        // balance can be skimmed repeatedly until the vault is drained.
        payable(msg.sender).transfer(amount);
        // missing: credited[msg.sender] = 0; totalCredited -= amount;
    }

    // Invariant the fuzzer breaks: the vault must always hold enough ETH to
    // honor totalCredited. After deposit();skim();skim() it does not.
    function echidna_vault_solvent() public view returns (bool) {
        return address(this).balance >= totalCredited;
    }
}
