// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// permit-frontrun-dos detector. DO NOT DEPLOY.
///
/// `zapDeposit` consumes an off-chain ERC20 permit signature but does not
/// wrap the permit() call in try/catch. A mempool observer can submit the
/// victim's permit directly to the token, advancing the nonce and causing
/// the victim's subsequent permit() call (and therefore the entire zap) to
/// revert. Classic user-facing DoS.

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

contract PermitFrontrunDosVuln {
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
        // Unwrapped permit call — front-run consumes the nonce, this reverts,
        // and the whole zap fails.
        IERC20Permit(token).permit(owner, address(this), amount, deadline, v, r, s);

        // Only reachable if the permit did not revert.
        IERC20(token).transferFrom(owner, vault, amount);
    }
}
