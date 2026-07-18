// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - admin-malicious-contract-injection
// CLEAN: setOracle has non-zero check, code-size check via Address.isContract,
// and a 2-day timelock before the oracle becomes active.

interface IOracle {
    function getPrice() external view returns (uint256);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

library Address {
    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract CleanLendingPool {
    IOracle public oracle;
    address public pendingOracle;
    uint256 public pendingOracleActivationTime;
    uint256 public constant TIMELOCK_DELAY = 2 days;
    bytes4 private constant IORACLE_ID = type(IOracle).interfaceId;

    IERC20 public collateral;
    IERC20 public debt;
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public debtBalance;
    address public owner;

    // CLEAN: non-zero, code-size, interface check + timelock proposal.
    function proposeOracle(address _oracle) external onlyOwner {
        require(_oracle != address(0), "zero address");
        require(Address.isContract(_oracle), "not a contract");
        require(IOracle(_oracle).supportsInterface(IORACLE_ID), "wrong interface");
        pendingOracle = _oracle;
        pendingOracleActivationTime = block.timestamp + TIMELOCK_DELAY;
        emit OracleUpdateProposed(_oracle, pendingOracleActivationTime);
    }

    // Activation only after timelock expires.
    function activateOracle() external onlyOwner {
        require(pendingOracle != address(0), "no pending oracle");
        require(block.timestamp >= pendingOracleActivationTime, "timelock active");
        oracle = IOracle(pendingOracle);
        emit OracleActivated(pendingOracle);
        pendingOracle = address(0);
    }

    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = collateralBalance[msg.sender] * price / 1e18;
        require(collateralValue >= amount * 150 / 100, "insufficient collateral");
        debtBalance[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }

    function liquidate(address borrower) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = collateralBalance[borrower] * price / 1e18;
        require(collateralValue < debtBalance[borrower], "healthy");
        collateral.transfer(msg.sender, collateralBalance[borrower]);
        collateralBalance[borrower] = 0;
        debtBalance[borrower] = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    event OracleUpdateProposed(address indexed proposed, uint256 activationTime);
    event OracleActivated(address indexed oracle);
}
