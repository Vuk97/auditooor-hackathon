// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal Balancer-style read-only reentrancy fixture. The pool both receives
// an ERC1155 hook callback during mutating ops AND exposes an unguarded view
// reading the same reserve/supply state. Third-party oracles pricing LP
// tokens via getReserves()/totalSupply() during the hook window read stale
// transient values.

contract ReadOnlyReentrancyVuln {
    uint256 internal reserve0;
    uint256 internal reserve1;
    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balance;

    // Callback receiver that mutates state (can be invoked mid-call).
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        returns (bytes4)
    {
        // A production pool would finish state updates after this hook —
        // the race window is exactly here.
        reserve0 += 1;
        return this.onERC1155Received.selector;
    }

    // Mutating entrypoint that invokes an external .call (potential reentry).
    function deposit(address to, uint256 amt) external {
        (bool ok, ) = to.call(abi.encodeWithSignature("onHook(uint256)", amt));
        require(ok);
        reserve0 += amt;           // state write AFTER external call
        _totalSupply += amt;
        _balance[to] += amt;
    }

    // VULN: unguarded view — external consumer can observe stale values
    // mid-callback when the pool's invariants are transiently broken.
    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balance[a];
    }
}
