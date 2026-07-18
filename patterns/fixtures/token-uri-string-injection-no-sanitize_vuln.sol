// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Meta {
    function symbol() external view returns (string memory);
    function name() external view returns (string memory);
}

contract NFTDescriptorVuln {
    IERC20Meta public immutable underlying;
    constructor(address u) { underlying = IERC20Meta(u); }

    // Detector MUST fire: splices underlying.symbol() directly into JSON.
    function tokenURI(uint256 id) external view returns (string memory) {
        return string(abi.encodePacked(
            '{"name":"Wrapped ',
            underlying.symbol(),
            '","description":"token #',
            toString(id),
            '"}'
        ));
    }

    function toString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v; uint256 len;
        while (n != 0) { len++; n /= 10; }
        bytes memory b = new bytes(len);
        while (v != 0) { len--; b[len] = bytes1(uint8(48 + (v % 10))); v /= 10; }
        return string(b);
    }
}
