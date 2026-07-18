pragma solidity ^0.8.20;

contract TokenizedBondSharesPositive {
    mapping(address => uint256) internal _balances;
    mapping(uint256 => mapping(address => uint256)) public validatorBondShares;
    mapping(uint256 => uint256) public totalValidatorBondShares;
    mapping(address => uint256) public primaryValidator;

    function bond(uint256 validatorId, uint256 shares) external {
        _balances[msg.sender] += shares;
        validatorBondShares[validatorId][msg.sender] += shares;
        totalValidatorBondShares[validatorId] += shares;
        if (primaryValidator[msg.sender] == 0) {
            primaryValidator[msg.sender] = validatorId;
        }
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _update(msg.sender, to, amount);
        return true;
    }

    function _update(address from, address to, uint256 amount) internal {
        _balances[from] -= amount;
        _balances[to] += amount;
    }

    function redeem(uint256 validatorId, uint256 shares) external {
        require(validatorBondShares[validatorId][msg.sender] >= shares, "bucket");
        validatorBondShares[validatorId][msg.sender] -= shares;
        totalValidatorBondShares[validatorId] -= shares;
        _balances[msg.sender] -= shares;
    }
}
