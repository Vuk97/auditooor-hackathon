pragma solidity ^0.8.20;

contract QueueIntakeNoFeePositive {
    struct Request {
        address requester;
        bytes payload;
    }

    Request[] public requestQueue;

    function submitRequest(bytes calldata payload) external {
        requestQueue.push(Request({requester: msg.sender, payload: payload}));
    }

    function processNext() external returns (bytes memory) {
        Request storage req = requestQueue[0];
        return req.payload;
    }
}
