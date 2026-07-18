// SPDX-License-Identifier: MIT
// Fixture: refund-computed-after-external-call-stale — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IRouter {
    function swap(uint256 amountIn, address tokenOut) external returns (uint256);
}

contract CleanVault {
    mapping(address => uint256) public refund;
    mapping(address => uint256) public pending;
    IRouter public router;
    IERC20 public tokenIn;

    constructor(address _router, address _tokenIn) {
        router = IRouter(_router);
        tokenIn = IERC20(_tokenIn);
    }

    // CLEAN: snapshot balance BEFORE the external call and derive
    // actualSpent from the locally-measured delta — the external contract
    // can no longer manipulate the refund basis.
    function swapAndRefund(uint256 providedAmount, address tokenOut) external {
        pending[msg.sender] += providedAmount;

        // Snapshot before — this is what makes the function safe.
        uint256 balanceBefore = tokenIn.balanceOf(address(this));

        uint256 out = router.swap(providedAmount, tokenOut);

        // Compute actualSpent from the local snapshot, never from an
        // external getter.
        uint256 balanceAfter = tokenIn.balanceOf(address(this));
        uint256 actualSpent = balanceBefore - balanceAfter;

        uint256 excess = providedAmount - actualSpent;
        refund[msg.sender] = excess;
        pending[msg.sender] -= providedAmount;

        out;
    }
}
