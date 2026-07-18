// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProtocolFeeMixedWithUserBalanceClean {
    address public owner;
    address public creator;
    uint256 public protocolFeePercent = 5e16;
    uint256 public creatorFeePercent = 2e16;
    uint256 public accruedProtocolFees;

    mapping(address => uint256) public reserveCredits;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor(address creator_) {
        owner = msg.sender;
        creator = creator_;
    }

    function buy() external payable {
        reserveCredits[msg.sender] += msg.value;
        _transferFees(msg.value);
    }

    function quoteReserveBalance() external view returns (uint256) {
        return address(this).balance - accruedProtocolFees;
    }

    function setProtocolFeePercent(uint256 newPercent) external onlyOwner {
        protocolFeePercent = newPercent;
    }

    function withdrawProtocolFees() external onlyOwner returns (uint256 withdrawn) {
        withdrawn = accruedProtocolFees;
        accruedProtocolFees = 0;
        payable(owner).transfer(withdrawn);
    }

    function _transferFees(uint256 grossAmount) internal {
        uint256 protocolFee = (grossAmount * protocolFeePercent) / 1e18;
        uint256 creatorFee = (grossAmount * creatorFeePercent) / 1e18;

        require(protocolFee + creatorFee <= grossAmount, "fee overflow");

        accruedProtocolFees += protocolFee;

        if (creatorFee > 0) {
            payable(creator).transfer(creatorFee);
        }

        reserveCredits[msg.sender] = grossAmount - protocolFee - creatorFee;
    }
}
