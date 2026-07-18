pragma solidity ^0.8.20;

contract ReentrantModifierMisuseNonReentrantFunctionsCallingEachOtherCaClean {
    bool private _entered;
    uint256 public counter;

    modifier nonReentrant() {
        require(!_entered, "reentrant");
        _entered = true;
        _;
        _entered = false;
    }

    function outer() external nonReentrant {
        _inner();
    }

    function _inner() internal {
        counter += 1;
    }
}
