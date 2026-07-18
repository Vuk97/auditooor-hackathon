// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32, bytes calldata) internal pure returns (address) { return address(0); }
}

contract UnsignedFeepipsAllowsRelayerSubstitutionVuln {
    bytes32 public constant INTENT_TYPEHASH =
        keccak256("IntentMessage(address to,address token,uint256 amount)");
    bytes32 public domainSeparator;

    function execute(address to, address token, uint256 amount, uint256 feePips, bytes calldata sig) external {
        // VULN: feePips not in struct hash — relayer can substitute any value.
        bytes32 structHash = keccak256(abi.encode(INTENT_TYPEHASH, to, token, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ECDSA.recover(digest, sig);
        require(signer != address(0), "bad sig");
        // Fee applied after, without being bound to signature.
        uint256 fee = amount * feePips / 10000;
        // ... transfer logic
        fee;
        to;
        token;
    }
}
