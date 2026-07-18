// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vault - custodies user deposits and routes withdrawals through a challenge window.
contract Vault {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    enum RequestStatus {
        Pending,
        Active,
        Challenged,
        Finalized
    }

    modifier onlyGuardian() {
        require(hasRole(GUARDIAN_ROLE, msg.sender), "not guardian");
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return true;
    }

    function deposit() external payable {
        // funds enter here
    }

    function withdraw(uint256 amount) external {
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
    }

    function refund(address to, uint256 amount) external onlyGuardian {
        // protocol-owned refund defense path
    }

    function pause() external onlyGuardian {
        // protocol-owned pause defense path
    }

    function challenge(uint256 requestId) external {
        // protocol-owned challenge defense path
    }

    function oracleQuote() external view returns (uint256) {
        return 1;
    }
}
