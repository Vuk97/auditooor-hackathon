// SPDX-License-Identifier: MIT
// Fixture: nonce-reset-enables-replay — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract MetaTxVuln is Ownable {
    // precondition: per-user nonce mapping.
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    function execute(
        address user,
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) external {
        require(nonces[user] == nonce, "bad nonce");
        // signature verification elided
        sig;
        nonces[user] += 1;
        balances[user] -= amount;
    }

    // VULN: admin-gated entrypoint zeroes a user's replay-protection nonce.
    // Any off-chain signature the user previously broadcast at nonces
    // 0..N-1 becomes valid again and can be replayed. Matches:
    //   - external_or_public
    //   - writes_storage_matching nonce
    //   - body_contains_regex `nonces[user] = 0`
    //   - onlyOwner modifier
    function resetNonce(address user) external onlyOwner {
        nonces[user] = 0;
    }

    // VULN: admin-gated `delete` form is semantically identical to zeroing
    // and triggers the same regex branch (`delete\s+nonces\[`).
    function adminReinit(address user) external onlyOwner {
        delete nonces[user];
    }
}
