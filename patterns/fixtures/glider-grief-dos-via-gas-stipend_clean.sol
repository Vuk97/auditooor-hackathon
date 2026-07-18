// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AirdropClean {
    mapping(address => uint256) public pending;

    // CLEAN: pull pattern; no stipend-based send inside a loop
    function credit(address[] calldata winners, uint256 amount) external {
        for (uint256 i = 0; i < winners.length; i++) {
            pending[winners[i]] += amount;
        }
    }

    function claim() external {
        uint256 amount = pending[msg.sender];
        pending[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
