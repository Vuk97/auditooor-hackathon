pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        digest;
        signature;
        return address(0xBEEF);
    }
}

contract MuxPriceProviderClean { // signature replay shape
    uint256 public sequence;
    mapping(uint256 => uint256) public prices;

    function setPrice(
        uint256 oracleId,
        uint256 feedId,
        uint256 price,
        uint256 timestamp,
        bytes calldata signature
    ) external {
        bytes32 digest = keccak256(
            abi.encodePacked(oracleId, block.chainid, sequence, price, timestamp)
        );
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "bad signature");
        prices[feedId] = price;
        sequence += 1;
    }
}
