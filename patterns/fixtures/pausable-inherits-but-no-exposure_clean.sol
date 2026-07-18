// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

// CLEAN: inherits Pausable AND exposes admin-gated pause()/unpause()
// functions that actually invoke the internal _pause() / _unpause() hooks.
// The contract-level `has_no_function_body_matching: (_pause\s*\(|_unpause\s*\(|emergencyPause)`
// precondition fails (because the body DOES contain _pause(...) / _unpause(...)),
// so the detector MUST NOT fire on this contract.
contract PausableClean is Pausable {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not-owner");
        _;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function claim() external whenNotPaused {
        // Reachable brake — admin can call pause() to halt this.
    }
}
