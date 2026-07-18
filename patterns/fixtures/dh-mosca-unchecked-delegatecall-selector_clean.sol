pragma solidity ^0.8.0;

contract MoscaDispatcherClean {
    address public impl;
    mapping(bytes4 => bool) public whitelistedSelectors;

    function dispatch(bytes4 selector, bytes calldata data) external payable {
        require(whitelistedSelectors[selector], "not allowed");
        (bool ok, bytes memory r) = impl.delegatecall(data);
        require(ok);
        assembly { return(add(r, 32), mload(r)) }
    }
}