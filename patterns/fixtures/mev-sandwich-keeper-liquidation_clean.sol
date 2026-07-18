// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainlink {
    function latestAnswer() external view returns (int256);
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

interface IUniV3PoolTWAP {
    // Uniswap-V3 TWAP surface: `observe` returns cumulative tick values.
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory);
}

// CLEAN: every keeper / liquidation entry point uses a time-weighted
// price (TWAP via `pool.observe`) and a commit-reveal / staleness
// threshold. Inline-spot sandwich windows are eliminated.
contract LendingKeeperClean {
    IChainlink public oracle;
    IUniV3PoolTWAP public pool;

    uint32 public constant TWAP_WINDOW = 1800; // 30 min TWAP
    uint256 public stalenessThreshold = 900;

    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;
    mapping(bytes32 => uint256) public commitPrice;
    mapping(address => uint256) public lastPriceUpdate;

    constructor(IChainlink _oracle, IUniV3PoolTWAP _pool) {
        oracle = _oracle;
        pool = _pool;
    }

    function _twap() internal view returns (uint256) {
        uint32[] memory windows = new uint32[](2);
        windows[0] = TWAP_WINDOW;
        windows[1] = 0;
        (int56[] memory cumulatives, ) = pool.observe(windows);
        int56 delta = cumulatives[1] - cumulatives[0];
        return uint256(uint56(delta / int56(uint56(TWAP_WINDOW))));
    }

    function liquidatePosition(address borrower, bytes32 commitment) external {
        // Commit-reveal: execution consumes a price committed in a
        // previous block, so same-tx manipulation cannot reach it.
        uint256 price = commitPrice[commitment];
        require(price > 0, "no commit");
        require(
            block.timestamp - lastPriceUpdate[borrower] < stalenessThreshold,
            "stale"
        );
        uint256 seize = (debt[borrower] * 110) / (price * 100);
        collateral[borrower] -= seize;
        debt[borrower] = 0;
    }

    function harvest() external {
        uint256 twap = _twap(); // TWAP, not spot
        require(twap > 0, "bad twap");
        collateral[msg.sender] += twap;
    }

    function keep(address borrower) external {
        uint256 twap = _twap();
        require(
            block.timestamp - lastPriceUpdate[borrower] < stalenessThreshold,
            "stale"
        );
        if (collateral[borrower] < twap) {
            debt[borrower] = 0;
        }
    }
}
