// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: caller performs a zero-address check before writing the lookup
// result into storage. Any of the require/if-revert idioms should
// independently suppress the match.

library SyntLib {
    function getRepresentation(uint256, address) internal pure returns (address) {
        return address(0x1234);
    }
}

contract CheckedLookupClean {
    mapping(uint256 => mapping(address => address)) public wrapperOf;
    mapping(bytes32 => address) public strategyOf;
    mapping(uint256 => address) public tokenRegistry;

    error ZeroAddress();

    // CLEAN shape 1: require(repr != address(0), ...) on the library return.
    function registerWrapper(uint256 fromChain, address token) external {
        address repr = SyntLib.getRepresentation(fromChain, token);
        require(repr != address(0), "missing representation");
        wrapperOf[fromChain][token] = repr;
    }

    // CLEAN shape 2: if (s == address(0)) revert custom-error form.
    function registerStrategy(bytes32 key) external {
        address s = factoryOf(key);
        if (s == address(0)) revert ZeroAddress();
        strategyOf[key] = s;
    }

    function factoryOf(bytes32) public pure returns (address) {
        return address(0xABCD);
    }

    // CLEAN shape 3: require on _getSynt result.
    function configureToken(uint256 id) external {
        address t = _getSynt(id);
        require(t != address(0), "no synt");
        tokenRegistry[id] = t;
    }

    function _getSynt(uint256) internal pure returns (address) {
        return address(0xBEEF);
    }
}
