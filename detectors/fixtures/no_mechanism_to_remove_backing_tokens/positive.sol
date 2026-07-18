pragma solidity ^0.8.20;

contract NoMechanismToRemoveBackingTokensPositive {
    address public owner;
    address[] public backingTokens;

    struct BackingTokenDetails {
        bool isBackingToken;
        address oracle;
    }

    mapping(address => BackingTokenDetails) public backingTokenDetailsForAddress;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addBackingToken(address _token, address _oracle) external onlyOwner {
        require(!backingTokenDetailsForAddress[_token].isBackingToken, "Already Backing Token");
        backingTokens.push(_token);
        backingTokenDetailsForAddress[_token] = BackingTokenDetails({
            isBackingToken: true,
            oracle: _oracle
        });
    }
}
