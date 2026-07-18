// SPDX-License-Identifier: MIT
// Minimal forge-std shim — bundled with the W5-D2 CE-concretizer fixture
// project so the auto-generated executable test can run without a network
// `forge install`. It implements only the surface the concretizer emits:
// `Test`, `vm.prank`, `vm.expectRevert`, `assertTrue`, `assertEq`.
pragma solidity ^0.8.20;

interface Vm {
    function prank(address) external;
    function expectRevert() external;
    function startPrank(address) external;
    function stopPrank() external;
}

contract Test {
    Vm internal constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition, string memory err) internal pure {
        require(condition, err);
    }

    function assertTrue(bool condition) internal pure {
        require(condition, "assertTrue failed");
    }

    function assertEq(uint256 a, uint256 b, string memory err) internal pure {
        require(a == b, err);
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "assertEq failed");
    }
}
