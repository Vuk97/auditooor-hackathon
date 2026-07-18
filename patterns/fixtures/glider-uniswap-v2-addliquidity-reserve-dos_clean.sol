// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IUniswapV2Pair {
    function mint(address) external returns (uint256);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32);
}

interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract LauncherClean {
    IUniswapV2Pair public pair;
    address public token;
    address public weth;

    function launch(uint256 amtToken, uint256 amtWeth) external {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        if (reserve0 > 0 && reserve1 > 0) {
            // use router path (not shown in fixture)
            return;
        }
        IERC20(token).transfer(address(pair), amtToken);
        IERC20(weth).transfer(address(pair), amtWeth);
        pair.mint(msg.sender);
    }
}
