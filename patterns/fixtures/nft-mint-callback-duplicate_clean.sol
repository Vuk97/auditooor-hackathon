// SPDX-License-Identifier: MIT
// Fixture: nft-mint-callback-duplicate — CLEAN
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

contract CleanDrop is ERC721Like, ReentrancyGuard {
    uint256 public nextId;
    mapping(address => bool) public hasMinted;

    // CLEAN: nonReentrant blocks callback reentry. Detector must not fire.
    function publicMint() external nonReentrant {
        require(!hasMinted[msg.sender], "already minted");
        _safeMint(msg.sender, nextId);
        nextId += 1;
        hasMinted[msg.sender] = true;
    }
}
