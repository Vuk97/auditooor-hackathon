// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal OZ Pausable stand-in so the fixture compiles under slither
// without node_modules. The internal _pause()/_unpause() hooks exist,
// whenNotPaused/whenPaused modifiers exist, but the inheriting contract
// never calls _pause / _unpause / emergencyPause anywhere in its body.
abstract contract Pausable {
    bool private _paused;
    event Paused(address account);
    event Unpaused(address account);
    modifier whenNotPaused() {
        require(!_paused, "paused");
        _;
    }
    modifier whenPaused() {
        require(_paused, "not-paused");
        _;
    }
    function paused() public view returns (bool) {
        return _paused;
    }
    function _pause() internal virtual {
        _paused = true;
        emit Paused(msg.sender);
    }
    function _unpause() internal virtual {
        _paused = false;
        emit Unpaused(msg.sender);
    }
}

// VULN: inherits Pausable. Decorates withdraw() with whenNotPaused.
// Does NOT expose an external pause()/unpause() function, does NOT call
// _pause() / _unpause() / emergencyPause from anywhere. The emergency
// brake is decorative — paused() is always false and cannot flip.
contract PausableVuln is Pausable {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function claim() external whenNotPaused {
        // Decorative whenNotPaused — _paused can never be set.
    }
}
