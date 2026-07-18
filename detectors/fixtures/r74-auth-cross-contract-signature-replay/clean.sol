// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface R74CleanSignatureVerifier {
    function recover(bytes32 digest, bytes calldata signature) external view returns (address);
}

contract R74AuthCrossContractSignatureReplayClean {
    bytes32 internal constant CLAIM_TYPEHASH =
        keccak256("Claim(address account,uint256 amount,uint256 deadline)");
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant NAME_HASH = keccak256("SiblingClaimVault");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    R74CleanSignatureVerifier internal immutable verifier;
    mapping(bytes32 => bool) public usedDigests;

    constructor(R74CleanSignatureVerifier _verifier) {
        verifier = _verifier;
    }

    function claim(address account, uint256 amount, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, account, amount, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = verifier.recover(digest, signature);

        require(signer == account, "bad signature");
        require(!usedDigests[digest], "used");
        usedDigests[digest] = true;
        amount;
    }
}
