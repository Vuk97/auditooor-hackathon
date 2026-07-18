// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32, bytes calldata) internal pure returns (address) { return address(0); }
}

contract UnsignedFeepipsAllowsRelayerSubstitutionClean {
    bytes32 public constant INTENT_TYPEHASH =
        keccak256("IntentMessage(address to,address token,uint256 amount,uint256 feePips)");
    bytes32 public domainSeparator;

    function execute(address to, address token, uint256 amount, uint256 feePips, bytes calldata sig) external {
        // CLEAN: feePips included in the struct hash.
        bytes32 structHash = keccak256(abi.encode(INTENT_TYPEHASH, to, token, amount, feePips));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ECDSA.recover(digest, sig);
        require(signer != address(0), "bad sig");
        uint256 fee = amount * feePips / 10000;
        fee;
        to;
        token;
    }
}
