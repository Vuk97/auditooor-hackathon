// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPyth {
    struct Price { int64 price; uint64 conf; int32 expo; uint256 publishTime; }
    function getPrice(bytes32 id) external view returns (Price memory);
    function getPriceNoOlderThan(bytes32 id, uint256 maxAge) external view returns (Price memory);
}

contract PythClean {
    IPyth public pyth;
    bytes32 public ethId;

    function getEthPrice() external view returns (int64) {
        IPyth.Price memory p = pyth.getPriceNoOlderThan(ethId, 300);
        return p.price;
    }

    function anotherFunction() external pure returns (uint256) {
        return 42;
    }
}