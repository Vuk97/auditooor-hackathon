// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ArbitraryCallViaDecodeClean {
    address public owner;
    mapping(address => bool) public approvedTargets;

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addApprovedTarget(address t) external onlyOwner {
        approvedTargets[t] = true;
    }

    // CLEAN: decoded target is checked against a governance-controlled whitelist
    // before the low-level call. Selector is also screened to prevent approval
    // redirections.
    function executeStrategy(bytes calldata blob) external returns (bytes memory) {
        (address target, bytes memory data) = abi.decode(blob, (address, bytes));
        require(approvedTargets[target], "TARGET_NOT_WHITELISTED");
        require(data.length >= 4, "BAD_DATA");
        bytes4 sel;
        assembly { sel := mload(add(data, 32)) }
        require(
            sel != bytes4(0x23b872dd) /* transferFrom */ &&
            sel != bytes4(0x095ea7b3) /* approve */ &&
            sel != bytes4(0xd505accf) /* permit */,
            "BAD_SELECTOR"
        );
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "STRATEGY_FAIL");
        return ret;
    }
}
