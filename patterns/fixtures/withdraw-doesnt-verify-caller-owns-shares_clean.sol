// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WithdrawNoOwnershipCheckClean {
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) private _allowances;

    // FIX: ERC-4626-style allowance consumption. Caller must either BE the
    // owner or have approved allowance for `amount` shares.
    function withdraw(uint256 amount, address receiver, address owner) external {
        if (msg.sender != owner) {
            uint256 allowed = _allowances[owner][msg.sender];
            require(allowed >= amount, "not approved");
            if (allowed != type(uint256).max) {
                _allowances[owner][msg.sender] = allowed - amount;
            }
        }
        shares[owner] -= amount;
        payable(receiver).transfer(amount);
    }

    // FIX: simpler ownership gate via msg.sender == owner.
    function redeem(uint256 shareAmt, address owner) external {
        require(msg.sender == owner, "not owner");
        shares[owner] -= shareAmt;
        payable(msg.sender).transfer(shareAmt);
    }

    receive() external payable {}
}
