pragma solidity ^0.8.20;

contract ErrorAssumptionOnUnsuccessfulCallOutputClean {
    function relay(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory returndata) = target.call(data);
        if (!success) {
            assembly {
                revert(add(returndata, 32), mload(returndata))
            }
        }

        return returndata;
    }
}
