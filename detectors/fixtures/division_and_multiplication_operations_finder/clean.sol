// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DivisionAndMultiplicationOperationsFinderClean {
    uint256 internal divisionMultiplier = 3;

    function _guard(uint256 divisor) internal pure {
        require(divisor != 0, "divisor=0");
    }

    function divisionQuote(uint256 amount, uint256 divisor) internal view returns (uint256) {
        _guard(divisor);
        return (amount * divisionMultiplier) / divisor;
    }
}
