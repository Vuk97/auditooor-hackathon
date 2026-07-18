// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same zap shape as the
/// vuln fixture but the permit() is wrapped in try/catch. If a mempool
/// observer front-runs with the victim's signature, the subsequent permit()
/// here reverts into the catch block and the zap proceeds to transferFrom
/// using the allowance the attacker's front-run already established.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

contract PermitFrontrunDosClean {
    address public vault;

    constructor(address _vault) {
        vault = _vault;
    }

    function zapDeposit(
        address token,
        address owner,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Defensive wrap: if a front-runner already consumed the nonce the
        // permit call reverts into the catch, we silently proceed, and the
        // transferFrom succeeds because the allowance is still set.
        try IERC20Permit(token).permit(owner, address(this), amount, deadline, v, r, s) {
            // noop
        } catch {
            // permit may already have been consumed — continue regardless
        }

        IERC20(token).transferFrom(owner, vault, amount);
    }
}
