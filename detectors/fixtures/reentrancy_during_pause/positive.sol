// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - reentrancy-during-pause
// VULN: onFlashLoan callback missing whenNotPaused + nonReentrant.
// Attacker can re-enter the paused protocol through the callback.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnPausableWithHook {
    bool public paused;
    address public owner;
    mapping(address => uint256) public balances;
    IERC20 public token;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
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

    // CLEAN: main user-facing deposit is guarded
    function deposit(uint256 amount) external whenNotPaused {
        balances[msg.sender] += amount;
        token.transfer(address(this), amount);
    }

    // CLEAN: main user-facing withdraw is guarded
    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    // VULN: flash loan callback - missing whenNotPaused AND nonReentrant
    // Attacker can call this during pause, executing external calls that re-enter
    function onFlashLoan(
        address initiator,
        address tokenAddr,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // external call before state cleanup - reentrancy vector
        token.transfer(initiator, amount);
        // reentrancy: attacker's fallback can re-call withdraw()
        // Note: withdraw has whenNotPaused but reentrancy state manipulation
        // happens before the check sees the dirty state
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
