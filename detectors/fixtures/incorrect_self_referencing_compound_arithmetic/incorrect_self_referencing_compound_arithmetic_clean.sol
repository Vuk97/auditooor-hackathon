pragma solidity ^0.8.20;

contract IncorrectSelfReferencingCompoundArithmeticClean {
    uint256 internal incorrectBalance = 10;
    uint256 internal incorrectDelta = 3;

    function incorrectSelfReferencingCompoundArithmetic() external returns (uint256) {
        uint256 nextBalance = incorrectBalance + incorrectDelta;
        incorrectBalance = nextBalance;
        return incorrectBalance;
    }
}
