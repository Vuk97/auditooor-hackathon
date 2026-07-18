// SPDX-License-Identifier: MIT
// Fixture: refund-computed-after-external-call-stale — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IRouter {
    function swap(uint256 amountIn, address tokenOut) external returns (uint256);
    function lastSpent() external view returns (uint256);
}

contract VulnVault {
    mapping(address => uint256) public refund;
    mapping(address => uint256) public pending;
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    // VULN: refund is derived from router.lastSpent() AFTER the external
    // swap. A reentrant token (ERC777/1363) inside the swap can re-enter
    // and mutate router state before this contract reads lastSpent(),
    // handing the attacker a stale/attacker-chosen `actualSpent`.
    // The function also persists the refund to storage AFTER the call —
    // post_external_call_writes_gte: 1 anchors on this.
    function swapAndRefund(uint256 providedAmount, address tokenOut) external {
        pending[msg.sender] += providedAmount;

        // External call — attacker re-enters here via transfer hook.
        uint256 out = router.swap(providedAmount, tokenOut);

        // Post-call read: attacker has already mutated router state.
        uint256 actualSpent = router.lastSpent();

        // Persist refund computed from the poisoned external getter.
        uint256 excess = providedAmount - actualSpent;
        refund[msg.sender] = excess;
        pending[msg.sender] -= providedAmount;

        // Silence unused warning.
        out;
    }
}
