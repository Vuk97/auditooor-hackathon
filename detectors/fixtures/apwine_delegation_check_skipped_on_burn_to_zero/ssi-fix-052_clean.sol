// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract APWinePrincipalTokenClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegatedAmount;
    mapping(address => mapping(address => uint256)) public delegation;
    mapping(address => uint256) public totalDelegationsReceived;

    uint256 private hookNonce;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function delegateYield(address receiver, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        delegatedAmount[msg.sender] += amount;
        delegation[msg.sender][receiver] += amount;
        totalDelegationsReceived[receiver] += amount;
    }

    function burn(uint256 amount) external {
        _beforeTokenTransfer(msg.sender, address(0), amount);
        balanceOf[msg.sender] -= amount;
    }

    function transfer(address to, uint256 amount) external {
        _beforeTokenTransfer(msg.sender, to, amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal {
        _touchTransferHook(from, to, amount);
        if (from != address(0)) {
            require(balanceOf[from] - delegatedAmount[from] >= amount, "delegation exceeds remaining balance");
        }
    }

    function _touchTransferHook(address from, address to, uint256 amount) internal {
        hookNonce = uint256(uint160(from)) ^ uint256(uint160(to)) ^ amount;
    }
}
