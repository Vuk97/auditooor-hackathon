// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRecoverEtherRecipient {
    function receiveShare() external payable;
}

contract RecoverEtherOverDistributionPositiveFixture {
    address public owner;
    uint256 public medium;

    constructor(address initialOwner) payable {
        owner = initialOwner;
        medium = msg.value;
    }

    function recoverEther(address payable to, address payable fallbackRecipient) external {
        require(msg.sender == owner, "owner");

        uint256 share = medium / 2;
        IRecoverEtherRecipient(to).receiveShare{value: share}();

        if (address(this).balance >= share) {
            IRecoverEtherRecipient(fallbackRecipient).receiveShare{value: share}();
        }
    }
}

