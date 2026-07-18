// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. The contract does on-
/// chain signature recovery but every signature-consuming entry point
/// binds and enforces a `deadline`, which matches the negated expiration
/// regex and suppresses the detector.
contract SigMissingExpirationClean {
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encodePacked("SigClean", block.chainid, address(this)));
    }

    // CLEAN: the digest includes `deadline` and the body enforces it
    // against block.timestamp.
    function fillOrder(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, to, amount, nonce, deadline));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad sig");
        require(nonces[signer] == nonce, "bad nonce");
        nonces[signer] = nonce + 1;
        balances[to] += amount;
    }

    // CLEAN variant: uses `validUntil` naming; still matches the negated
    // expiration regex.
    function claimVoucher(
        address beneficiary,
        uint256 amount,
        uint256 validUntil,
        bytes calldata signature
    ) external {
        require(block.timestamp <= validUntil, "expired");
        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, beneficiary, amount, validUntil));
        require(isValidSignatureNow(beneficiary, hash, signature), "bad sig");
        balances[beneficiary] += amount;
    }

    function isValidSignatureNow(address, bytes32, bytes calldata) internal pure returns (bool) {
        return true;
    }
}
