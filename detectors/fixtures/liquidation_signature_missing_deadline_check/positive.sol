// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LiquidationSignatureMissingDeadlinePositive {
    address public immutable oracleSigner;
    mapping(address => bool) public liquidated;

    constructor(address _oracleSigner) {
        oracleSigner = _oracleSigner;
    }

    function liquidateWithSig(
        address borrower,
        uint256 maxDebtToRepay,
        uint256 deadline,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        bytes32 digest = keccak256(
            abi.encodePacked(address(this), borrower, maxDebtToRepay, deadline)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == oracleSigner, "bad sig");
        liquidated[borrower] = true;
    }
}
