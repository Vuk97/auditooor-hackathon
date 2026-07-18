// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
}

contract ApprovalPool {
    mapping(address => mapping(address => uint256)) public allowance;
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        return true;
    }
}

contract RouterArbTargetVuln {
    ApprovalPool public pool;
    mapping(address => uint256) public balances;
    
    constructor(address _pool) {
        pool = ApprovalPool(_pool);
    }
    
    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "fail");
        return ret;
    }
    
    function delegateExecute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "fail");
        return ret;
    }
    
    function seedApprovals(address token, address spender) external {
        IERC20(token).approve(spender, type(uint256).max);
    }
}