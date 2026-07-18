// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Contract wraps user-supplied ETH into WETH and immediately calls
// add_liquidity on a Curve pool WITHOUT checking whether the pool uses
// native ETH or WETH at coins(0). If the target pool is a native-ETH pool,
// the ERC20 accounting path on add_liquidity either reverts or silently
// accepts the WETH without crediting the ETH leg — funds stuck.
//
// Mirror VULN in `withdrawAsETH`: unconditionally unwraps via WETH.withdraw
// after a `remove_liquidity_one_coin` call, assuming the pool returns WETH.
// On a native-ETH pool the pool returns ETH and the `weth.withdraw` call
// reverts; on a WETH pool the call wraps correctly. No branch.

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface ICurvePool {
    function add_liquidity(uint256[2] calldata amounts, uint256 minMint) external payable returns (uint256);
    function remove_liquidity_one_coin(uint256 lp, int128 i, uint256 minOut) external returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy) external payable returns (uint256);
    function coins(uint256 i) external view returns (address);
}

contract CurveEthStrategyVuln {
    IWETH     public immutable weth;
    ICurvePool public immutable pool;

    constructor(address _weth, address _pool) {
        weth = IWETH(_weth);
        pool = ICurvePool(_pool);
    }

    // VULN: wraps msg.value to WETH, approves pool, calls add_liquidity on
    // the ETH-side index (0). No check of pool.coins(0) vs native-ETH
    // sentinel. On a native-ETH pool the pool expects msg.value, not an
    // ERC20 transfer, and the WETH-amount path silently mis-settles.
    function depositETH() external payable returns (uint256 minted) {
        weth.deposit{value: msg.value}();
        weth.approve(address(pool), msg.value);
        uint256[2] memory amounts;
        amounts[0] = msg.value;
        amounts[1] = 0;
        minted = pool.add_liquidity(amounts, 0);
    }

    // VULN mirror: removes liquidity then unconditionally unwraps via
    // WETH.withdraw. On a native-ETH pool the pool returns ETH directly
    // and the withdraw call reverts. Pattern fires because the body both
    // calls remove_liquidity_one_coin and invokes weth.withdraw, with no
    // IS_NATIVE_POOL / useNativeEth / sentinel branch.
    function withdrawAsETH(uint256 lpAmount) external returns (uint256 amountETH) {
        amountETH = pool.remove_liquidity_one_coin(lpAmount, 0, 0);
        weth.withdraw(amountETH);
        (bool ok, ) = msg.sender.call{value: amountETH}("");
        require(ok, "eth xfer");
    }
}
