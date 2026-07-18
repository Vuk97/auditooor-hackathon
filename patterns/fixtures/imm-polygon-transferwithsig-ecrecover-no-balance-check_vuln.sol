// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Polygon MRC20-style gasless transfer. ecrecover return is not
// zero-checked and _transfer has no balance >= amount guard.
contract MRC20Vuln {
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
        // No signer != address(0) check.
        require(!usedSig[keccak256(sig)], "replay");
        usedSig[keccak256(sig)] = true;
        _transferFrom(signer, to, amount);
    }

    function _transferFrom(address from, address to, uint256 amount) internal {
        // Missing: require(balances[from] >= amount, "insufficient");
        unchecked {
            balances[from] -= amount;
        }
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
