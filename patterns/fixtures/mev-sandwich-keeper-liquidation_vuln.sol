// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal Chainlink + Uniswap stand-ins so the fixture compiles.
interface IChainlink {
    function latestAnswer() external view returns (int256);
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

interface IUniV3Pool {
    function slot0()
        external
        view
        returns (uint160 sqrtPriceX96, int24, uint16, uint16, uint16, uint8, bool);
}

// VULN: `liquidatePosition` and `harvest` each derive the execution
// price from a single-tx oracle read (Chainlink `latestAnswer` or
// `pool.slot0`) with no TWAP / commit-reveal / staleness guard. A
// searcher can perturb the source within the same block, trigger the
// keeper path at a favourable price, and back-run to unwind.
contract LendingKeeperVuln {
    IChainlink public oracle;
    IUniV3Pool public pool;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;

    constructor(IChainlink _oracle, IUniV3Pool _pool) {
        oracle = _oracle;
        pool = _pool;
    }

    function liquidatePosition(address borrower) external {
        int256 spot = oracle.latestAnswer(); // inline oracle read
        require(spot > 0, "bad oracle");
        uint256 price = uint256(spot);
        uint256 seize = (debt[borrower] * 110) / (price * 100);
        collateral[borrower] -= seize;
        debt[borrower] = 0;
    }

    function harvest() external {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0(); // inline spot
        uint256 px = uint256(sqrtPriceX96);
        // ...rebalance logic that trusts `px`...
        collateral[msg.sender] += px;
    }

    function keep(address borrower) external {
        (, int256 answer, , , ) = oracle.latestRoundData();
        require(answer > 0, "bad oracle");
        if (collateral[borrower] < uint256(answer)) {
            debt[borrower] = 0;
        }
    }
}
