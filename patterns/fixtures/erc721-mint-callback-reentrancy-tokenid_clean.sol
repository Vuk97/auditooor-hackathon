// SPDX-License-Identifier: MIT
// Fixture: erc721-mint-callback-reentrancy-tokenid — CLEAN
// Detector MUST NOT fire on this contract.
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
            IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "");
        }
    }
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract StakingMinterClean is ERC721Like, ReentrancyGuard {
    uint256 public nextId;
    mapping(uint256 => address) public stakedBy;
    mapping(address => uint256) public stakeCount;

    // CLEAN: nonReentrant blocks cross-function reentry via onERC721Received.
    function mintAndStake() external nonReentrant {
        uint256 id = nextId;
        _safeMint(msg.sender, id);
        stakedBy[id] = msg.sender;
        stakeCount[msg.sender] += 1;
        nextId = id + 1;
    }

    function deposit(uint256 id) external nonReentrant {
        require(stakedBy[id] == msg.sender, "not owner");
        stakeCount[msg.sender] += 1;
    }
}
