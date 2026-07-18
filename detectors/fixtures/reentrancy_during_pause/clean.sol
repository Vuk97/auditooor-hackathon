// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - reentrancy-during-pause
// CLEAN: onFlashLoan callback has both whenNotPaused AND nonReentrant guard.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract CleanPausableWithHook {
    bool public paused;
    bool private _locked;
    address public owner;
    mapping(address => uint256) public balances;
    IERC20 public token;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function deposit(uint256 amount) external whenNotPaused nonReentrant {
        balances[msg.sender] += amount;
        token.transfer(address(this), amount);
    }

    function withdraw(uint256 amount) external whenNotPaused nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    // CLEAN: flash loan callback has whenNotPaused AND nonReentrant.
    function onFlashLoan(
        address initiator,
        address tokenAddr,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external whenNotPaused nonReentrant returns (bytes32) {
        token.transfer(initiator, amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
