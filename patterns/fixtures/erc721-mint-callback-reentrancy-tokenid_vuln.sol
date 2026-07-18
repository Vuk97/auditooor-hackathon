// SPDX-License-Identifier: MIT
// Fixture: erc721-mint-callback-reentrancy-tokenid — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata)
        external returns (bytes4);
}

abstract contract ERC721Like {
    mapping(uint256 => address) internal _owners;

    function _mint(address to, uint256 tokenId) internal {
        _owners[tokenId] = to;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _mint(to, tokenId);
        if (to.code.length > 0) {
            // External call into attacker-controlled recipient.
            IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "");
        }
    }
}

contract StakingMinter is ERC721Like {
    uint256 public nextId;
    mapping(uint256 => address) public stakedBy;
    mapping(address => uint256) public stakeCount;

    // VULN: no nonReentrant. _safeMint -> callback can re-enter `deposit`
    // (a DIFFERENT mutating function) before the mint's post-call state
    // writes (nextId, stakedBy, stakeCount) complete. Unlike the same-
    // function duplicate-ID case, this one corrupts stake accounting.
    function mintAndStake() external {
        uint256 id = nextId;
        _safeMint(msg.sender, id);          // external call
        stakedBy[id] = msg.sender;          // post-call state write
        stakeCount[msg.sender] += 1;
        nextId = id + 1;
    }

    // Cross-function target that the mint callback can re-enter.
    function deposit(uint256 id) external {
        require(stakedBy[id] == msg.sender, "not owner");
        stakeCount[msg.sender] += 1;
    }
}
