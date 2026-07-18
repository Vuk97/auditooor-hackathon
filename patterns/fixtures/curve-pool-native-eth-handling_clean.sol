// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Branches on IS_NATIVE_POOL / pool.coins(0) == SENTINEL_ETH before
// deciding whether to wrap/unwrap WETH or forward msg.value directly. The
// negative guard regex sees `IS_NATIVE_POOL` / `useNativeEth` / `pool.coins(0)`
// and suppresses the match.

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
}

interface ICurvePool {
    function add_liquidity(uint256[2] calldata amounts, uint256 minMint) external payable returns (uint256);
    function remove_liquidity_one_coin(uint256 lp, int128 i, uint256 minOut) external returns (uint256);
    function coins(uint256 i) external view returns (address);
}

contract CurveEthStrategyClean {
    address internal constant SENTINEL_ETH = 0xEeeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeE;

    IWETH      public immutable weth;
    ICurvePool public immutable pool;
    bool       public immutable IS_NATIVE_POOL;

    constructor(address _weth, address _pool) {
        weth = IWETH(_weth);
        pool = ICurvePool(_pool);
        IS_NATIVE_POOL = (ICurvePool(_pool).coins(0) == SENTINEL_ETH);
    }

    // CLEAN: branch on IS_NATIVE_POOL. Native-ETH pools receive msg.value
    // directly; WETH pools get the ERC20 path.
    function depositETH(uint256 minMint) external payable returns (uint256 minted) {
        uint256[2] memory amounts;
        amounts[0] = msg.value;
        if (IS_NATIVE_POOL) {
            minted = pool.add_liquidity{value: msg.value}(amounts, minMint);
        } else {
            weth.deposit{value: msg.value}();
            weth.approve(address(pool), msg.value);
            minted = pool.add_liquidity(amounts, minMint);
        }
        require(minted >= minMint, "curve: min mint");
    }

    // CLEAN mirror: branch before unwrap.
    function withdrawAsETH(uint256 lpAmount, uint256 minOut) external returns (uint256 amountETH) {
        amountETH = pool.remove_liquidity_one_coin(lpAmount, 0, minOut);
        if (!IS_NATIVE_POOL) {
            weth.withdraw(amountETH);
        }
        (bool ok, ) = msg.sender.call{value: amountETH}("");
        require(ok, "eth xfer");
    }
}
