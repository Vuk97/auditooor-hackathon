pragma solidity ^0.8.20;

abstract contract MinimalPausable {
    bool internal _paused;

    modifier whenNotPaused() {
        require(!_paused, "paused");
        _;
    }

    function _pause() internal {
        _paused = true;
    }

    function _unpause() internal {
        _paused = false;
    }
}

contract PausableOnlyPauseExposed is MinimalPausable {
    address public owner;
    uint256 public deposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function deposit(uint256 amount) external whenNotPaused {
        deposits += amount;
    }
}
