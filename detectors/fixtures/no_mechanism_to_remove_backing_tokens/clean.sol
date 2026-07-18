pragma solidity ^0.8.20;

contract NoMechanismToRemoveBackingTokensClean {
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

    function removeBackingToken(address _token) external onlyOwner {
        require(backingTokenDetailsForAddress[_token].isBackingToken, "Missing Backing Token");
        for (uint256 i = 0; i < backingTokens.length; ++i) {
            if (backingTokens[i] == _token) {
                backingTokens[i] = backingTokens[backingTokens.length - 1];
                backingTokens.pop();
                break;
            }
        }
        delete backingTokenDetailsForAddress[_token];
    }

    function updateBackingTokenOracle(address _token, address _oracle) external onlyOwner {
        require(backingTokenDetailsForAddress[_token].isBackingToken, "Missing Backing Token");
        backingTokenDetailsForAddress[_token].oracle = _oracle;
    }
}
