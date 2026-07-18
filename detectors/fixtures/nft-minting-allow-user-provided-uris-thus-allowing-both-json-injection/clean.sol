pragma solidity ^0.8.20;

contract ValidatedUserProvidedUriERC721 {
    mapping(uint256 => string) private _tokenURIs;
    uint256 private _nextTokenId;

    function publicMint(string calldata approvedUri) external returns (uint256) {
        _validateURI(approvedUri);
        uint256 tokenId = ++_nextTokenId;
        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, approvedUri);
        return tokenId;
    }

    function _validateURI(string memory candidate) internal pure {
        bytes memory raw = bytes(candidate);
        require(raw.length > 7, "uri-too-short");
        require(raw.length < 96, "uri-too-long");
        require(raw[0] != bytes1('"'), "uri-leading-quote");
    }

    function _safeMint(address to, uint256 tokenId) internal pure {
        to;
        tokenId;
    }

    function _setTokenURI(uint256 tokenId, string memory uri_) internal {
        _tokenURIs[tokenId] = uri_;
    }
}
