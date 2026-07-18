pragma solidity ^0.8.20;

contract QueueIntakeNoFeeClean {
    struct Request {
        address requester;
        bytes payload;
    }

    Request[] public requestQueue;
    mapping(address => uint256) public pendingCount;
    uint256 public intakeFee = 0.01 ether;
    uint256 public userQuota = 2;

    function submitRequest(bytes calldata payload) external payable {
        require(msg.value >= intakeFee, "fee");
        require(pendingCount[msg.sender] < userQuota, "quota");
        pendingCount[msg.sender] += 1;
        requestQueue.push(Request({requester: msg.sender, payload: payload}));
    }

    function processNext() external returns (bytes memory) {
        Request storage req = requestQueue[0];
        pendingCount[req.requester] -= 1;
        return req.payload;
    }
}
