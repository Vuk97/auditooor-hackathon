// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// signature-missing-expiration detector. DO NOT DEPLOY.
///
/// The contract verifies signatures via ecrecover + per-signer nonce and
/// even binds an EIP-712-style domain hash into the digest. But the
/// signed payload carries no `deadline` / `expiry` / `validUntil`, so a
/// limit order signed at $1500 WETH remains fillable months later when
/// ETH is at $3000. Cross-chain replay is blocked by the domain; stale-
/// condition replay is not.
contract SigMissingExpirationVuln {
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encodePacked("SigVuln", block.chainid, address(this)));
    }

    // VULN: the digest authenticates signer, to, amount, nonce and the
    // domain — but NOT an expiration. `deadline`, `expiry`, `validUntil`,
    // `issuedAt` are all absent from the body.
    function fillOrder(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, to, amount, nonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad sig");
        require(nonces[signer] == nonce, "bad nonce");
        nonces[signer] = nonce + 1;
        balances[to] += amount;
    }

    // VULN variant: a 1271 SignatureChecker consumer with the same flaw.
    function claimVoucher(
        address beneficiary,
        uint256 amount,
        bytes calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, beneficiary, amount));
        require(isValidSignatureNow(beneficiary, hash, signature), "bad sig");
        balances[beneficiary] += amount;
    }

    function isValidSignatureNow(address, bytes32, bytes calldata) internal pure returns (bool) {
        return true;
    }
}
