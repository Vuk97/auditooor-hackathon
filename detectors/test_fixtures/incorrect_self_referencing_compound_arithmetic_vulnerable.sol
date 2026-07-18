pragma solidity ^0.8.20;

contract IncorrectSelfReferencingCompoundArithmeticVulnerable {
    uint256 internal incorrectBalance = 10;
    uint256 internal incorrectDelta = 3;

    function incorrectSelfReferencingCompoundArithmetic() external returns (uint256) {
        incorrectBalance += incorrectBalance + incorrectDelta;
        return incorrectBalance;
    }
}
