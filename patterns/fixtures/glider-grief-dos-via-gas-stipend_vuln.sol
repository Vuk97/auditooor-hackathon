// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AirdropVuln {
    // VULN: payable.transfer uses 2300 stipend; one malicious recipient DoSes all
    function airdrop(address[] calldata winners, uint256 amount) external {
        for (uint256 i = 0; i < winners.length; i++) {
            payable(winners[i]).transfer(amount);
        }
    }
}
