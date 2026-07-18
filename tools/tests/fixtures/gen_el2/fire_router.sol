// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A bytes4 -> address handler router set with NO dedup / collision reject.
// GEN-EL2 must FIRE (router-map, no-add-collision-require): an attacker or a
// benign re-registration overwrites the routed target for a selector.
contract FireRouter {
    mapping(bytes4 => address) public routes;

    function register(bytes4 selector, address impl) external {
        // no `require(routes[selector] == address(0))` collision reject.
        routes[selector] = impl;
    }

    fallback() external payable {
        address impl = routes[msg.sig];
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok, "route failed");
    }
}
