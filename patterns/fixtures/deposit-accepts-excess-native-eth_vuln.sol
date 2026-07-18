// SPDX-License-Identifier: MIT
// Fixture: deposit-accepts-excess-native-eth — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract VulnVault {
    mapping(address => uint256) public balances;
    uint256 public constant FIXED_COST = 1 ether;

    // VULN: payable, reads msg.value, no equality check, no refund of the
    // overpaid surplus. User overpaying ETH has the extra silently absorbed
    // into the contract balance with no withdrawal path.
    function depositETH() external payable {
        require(msg.value > 0, "zero value");
        // Credits against FIXED_COST regardless of msg.value; overpayment is
        // trapped.
        balances[msg.sender] += FIXED_COST;
    }
}
