// SPDX-License-Identifier: MIT
// Fixture: nft-mint-callback-duplicate — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata)
        external returns (bytes4);
}

// Minimal ERC721-like base that routes through onERC721Received on safe mint.
abstract contract ERC721Like {
    mapping(uint256 => address) internal _owners;

    function _mint(address to, uint256 tokenId) internal {
        _owners[tokenId] = to;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _mint(to, tokenId);
        // Routes to attacker-controlled recipient before caller's state write.
        if (to.code.length > 0) {
            IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "");
        }
    }
}

contract VulnDrop is ERC721Like {
    uint256 public nextId;
    mapping(address => bool) public hasMinted;

    // VULN: _safeMint triggers onERC721Received BEFORE nextId/hasMinted update.
    // Attacker re-enters publicMint() in the callback — duplicate tokenId and
    // bypassed one-per-wallet cap.
    function publicMint() external {
        require(!hasMinted[msg.sender], "already minted");
        _safeMint(msg.sender, nextId);
        nextId += 1;
        hasMinted[msg.sender] = true;
    }
}
