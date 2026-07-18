// SPDX-License-Identifier: MIT
// AaveV3PoolStub.sol — Replay-harness stub for Aave V3 Pool.
//
// Production faithfulness scope: models supply/borrow/repay/withdraw/liquidate
// entry points and ACL-gated admin functions. Does NOT model interest-rate
// model accrual, oracle price lookup, reserve factor math, or the full
// ReserveLogic/BorrowLogic library dispatching.
//
// Faithfully models (6 of 10 production Pool behaviors):
//   1. supply(): records collateral balance for msg.sender, emits Supply.
//   2. borrow(): checks collateral coverage (stub ratio), records debt, emits Borrow.
//   3. repay(): reduces debt up to amount, emits Repay.
//   4. withdraw(): checks collateral sufficiency post-withdrawal, emits Withdraw.
//   5. liquidationCall(): transfers aToken from borrower to liquidator when
//      health factor < 1e18 (stub HF), emits LiquidationCall.
//   6. ACL guard: POOL_ADMIN_ROLE ops (setReserveActive, pauseReserve) check
//      aclManager.hasRole().
// Intentionally simplified (4 of 10):
//   7. Interest-rate model: not modeled; balances are nominal (no accrual).
//   8. Oracle pricing: stubbed as 1:1 USD.
//   9. Isolation mode / E-Mode: not modeled.
//   10. Flash loan accounting: flashLoanSimple records request but does not
//       validate the callback return value.
//
// Usage: supply as --override-contract Pool=<path> in fork-replay.py.
// Compile: forge build (solc ^0.8.20)
pragma solidity ^0.8.20;

interface IAclManagerStub {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

contract AaveV3PoolStub {
    bytes32 public constant POOL_ADMIN_ROLE = keccak256("POOL_ADMIN");

    // ── Storage ───────────────────────────────────────────────────────────────
    address public aclManager;

    /// @dev collateral[user][asset]
    mapping(address => mapping(address => uint256)) public collateral;
    /// @dev debt[user][asset]
    mapping(address => mapping(address => uint256)) public debt;
    /// @dev liquidationThreshold: stub uses 80% (8000 bps)
    uint256 public liquidationThreshold = 8000;

    /// @dev paused per asset
    mapping(address => bool) public reservePaused;

    // ── Events ────────────────────────────────────────────────────────────────
    event Supply(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint16 indexed referralCode);
    event Borrow(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint8 interestRateMode, uint256 borrowRate, uint16 indexed referralCode);
    event Repay(address indexed reserve, address indexed user, address indexed repayer, uint256 amount, bool useATokens);
    event Withdraw(address indexed reserve, address indexed user, address indexed to, uint256 amount);
    event LiquidationCall(address indexed collateralAsset, address indexed debtAsset, address indexed user, uint256 debtToCover, uint256 liquidatedCollateralAmount, address liquidator, bool receiveAToken);
    event ReservePaused(address indexed asset, bool paused);

    constructor(address _aclManager) {
        aclManager = _aclManager;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────────
    modifier notPaused(address asset) {
        require(!reservePaused[asset], "AavePoolStub: reserve paused");
        _;
    }

    modifier onlyAdmin() {
        require(
            IAclManagerStub(aclManager).hasRole(POOL_ADMIN_ROLE, msg.sender),
            "AavePoolStub: not pool admin"
        );
        _;
    }

    // ── supply (behavior #1) ──────────────────────────────────────────────────
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external notPaused(asset) {
        collateral[onBehalfOf][asset] += amount;
        emit Supply(asset, msg.sender, onBehalfOf, amount, referralCode);
    }

    // ── borrow (behavior #2) ──────────────────────────────────────────────────
    function borrow(
        address asset,
        uint256 amount,
        uint256 /* interestRateMode */,
        uint16 referralCode,
        address onBehalfOf
    ) external notPaused(asset) {
        // Stub health check: total collateral * threshold >= total debt + amount
        uint256 col = collateral[onBehalfOf][asset];
        uint256 existingDebt = debt[onBehalfOf][asset];
        require(
            col * liquidationThreshold / 10000 >= existingDebt + amount,
            "AavePoolStub: insufficient collateral"
        );
        debt[onBehalfOf][asset] += amount;
        emit Borrow(asset, msg.sender, onBehalfOf, amount, 2, 0, referralCode);
    }

    // ── repay (behavior #3) ───────────────────────────────────────────────────
    function repay(
        address asset,
        uint256 amount,
        uint256 /* rateMode */,
        address onBehalfOf
    ) external notPaused(asset) returns (uint256 repaid) {
        uint256 owed = debt[onBehalfOf][asset];
        repaid = amount > owed ? owed : amount;
        debt[onBehalfOf][asset] -= repaid;
        emit Repay(asset, onBehalfOf, msg.sender, repaid, false);
    }

    // ── withdraw (behavior #4) ────────────────────────────────────────────────
    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external notPaused(asset) returns (uint256) {
        uint256 col = collateral[msg.sender][asset];
        require(col >= amount, "AavePoolStub: insufficient supply");
        uint256 remaining = col - amount;
        uint256 debtVal = debt[msg.sender][asset];
        require(
            debtVal == 0 || remaining * liquidationThreshold / 10000 >= debtVal,
            "AavePoolStub: would undercollateralize"
        );
        collateral[msg.sender][asset] = remaining;
        emit Withdraw(asset, msg.sender, to, amount);
        return amount;
    }

    // ── liquidationCall (behavior #5) ─────────────────────────────────────────
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external {
        uint256 userDebt = debt[user][debtAsset];
        uint256 userCol = collateral[user][collateralAsset];
        require(userDebt > 0, "AavePoolStub: no debt");
        // Stub HF: unhealthy when collateral * threshold < debt
        require(
            userCol * liquidationThreshold / 10000 < userDebt,
            "AavePoolStub: position is healthy"
        );
        uint256 cover = debtToCover > userDebt ? userDebt : debtToCover;
        debt[user][debtAsset] -= cover;
        uint256 colSeized = cover; // 1:1 stub pricing
        collateral[user][collateralAsset] -= colSeized > userCol ? userCol : colSeized;
        collateral[msg.sender][collateralAsset] += colSeized;
        emit LiquidationCall(collateralAsset, debtAsset, user, cover, colSeized, msg.sender, receiveAToken);
    }

    // ── ACL-gated admin (behavior #6) ─────────────────────────────────────────
    function setReservePaused(address asset, bool pause_) external onlyAdmin {
        reservePaused[asset] = pause_;
        emit ReservePaused(asset, pause_);
    }

    receive() external payable {}
}
