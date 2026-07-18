pragma solidity ^0.8.20;

contract UnsafeUserProvidedUriERC721 {
    mapping(uint256 => string) private _tokenURIs;
    uint256 private _nextTokenId;

    function publicMint(string calldata userProvidedUri) external returns (uint256) {
        uint256 tokenId = ++_nextTokenId;
        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, userProvidedUri);
        return tokenId;
    }

    function _safeMint(address to, uint256 tokenId) internal pure {
        to;
        tokenId;
    }

    function _setTokenURI(uint256 tokenId, string memory uri_) internal {
        _tokenURIs[tokenId] = uri_;
    }
}
