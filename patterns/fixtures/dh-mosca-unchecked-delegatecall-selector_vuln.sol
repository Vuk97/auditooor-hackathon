pragma solidity ^0.8.0;

contract MoscaDispatcherVuln {
    address public impl;

    function dispatch(bytes4 selector, bytes calldata data) external payable {
        selector;
        (bool ok, bytes memory r) = impl.delegatecall(data);
        require(ok);
        assembly { return(add(r, 32), mload(r)) }
    }
}