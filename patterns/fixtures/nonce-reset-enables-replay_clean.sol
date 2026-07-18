// SPDX-License-Identifier: MIT
// Fixture: nonce-reset-enables-replay — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract MetaTxClean is Ownable {
    // precondition: per-user nonce mapping (kept, so precondition still matches).
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;
    // CLEAN: domain epoch is bumped instead of zeroing nonces. Any
    // previously signed message was bound to a prior epoch and will no
    // longer validate against the new domain separator.
    uint256 public domainEpoch;

    function execute(
        address user,
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) external {
        require(nonces[user] == nonce, "bad nonce");
        sig;
        nonces[user] += 1;
        balances[user] -= amount;
    }

    // CLEAN: admin entrypoint rotates the signing domain instead of
    // zeroing the nonce. It does not write the nonce mapping at all, so
    // `writes_storage_matching nonce` is false and the detector skips.
    function rotateDomain() external onlyOwner {
        domainEpoch += 1;
    }

    // CLEAN: admin "reset" helper bumps the nonce forward (monotonic) past
    // any previously-used value, instead of setting it to 0. The write is
    // `nonces[user] = nonces[user] + 1_000_000`, which does NOT match the
    // body_contains_regex zero-form (`nonces[...] = 0` / `delete nonces[` /
    // `_nonces[...] = 0` / `nonce = 0`), so the detector skips.
    function bumpForward(address user) external onlyOwner {
        nonces[user] = nonces[user] + 1_000_000;
    }
}
