// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MRC20Clean {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public usedSig;

    function transferWithSig(
        bytes calldata sig,
        uint256 amount,
        bytes32 data,
        address to
    ) external {
        require(sig.length == 65, "sig len");
        bytes32 digest = keccak256(abi.encodePacked(amount, data, to, address(this)));
        (uint8 v, bytes32 r, bytes32 s) = _split(sig);
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        require(!usedSig[keccak256(sig)], "replay");
        usedSig[keccak256(sig)] = true;
        require(balances[signer] >= amount, "insufficient");
        balances[signer] -= amount;
        balances[to] += amount;
    }

    function _split(bytes calldata sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
    }
}
