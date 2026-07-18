// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: caller writes the result of a library/factory lookup directly
// to storage without checking for address(0).

library SyntLib {
    function getRepresentation(uint256, address) internal pure returns (address) {
        return address(0); // simulate "not yet deployed" sentinel
    }
}

interface IFactory {
    function factoryOf(bytes32 key) external view returns (address);
}

contract UncheckedLookupVuln {
    address public bridgeFactory;
    mapping(uint256 => mapping(address => address)) public wrapperOf;
    mapping(bytes32 => address) public strategyOf;
    mapping(uint256 => address) public tokenRegistry;

    // VULN shape 1: SyntLib.getRepresentation routed straight into storage.
    function registerWrapper(uint256 fromChain, address token) external {
        wrapperOf[fromChain][token] = SyntLib.getRepresentation(fromChain, token);
    }

    // VULN shape 2: local-variable factoryOf assignment, no zero check.
    function registerStrategy(bytes32 key) external {
        address s = factoryOf(key);
        strategyOf[key] = s;
    }

    function factoryOf(bytes32) public pure returns (address) {
        return address(0);
    }

    // VULN shape 3: _getSynt internal wrapper written to storage, no check.
    function configureToken(uint256 id) external {
        tokenRegistry[id] = _getSynt(id);
    }

    function _getSynt(uint256) internal pure returns (address) {
        return address(0);
    }
}
