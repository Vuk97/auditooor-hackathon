pragma solidity ^0.8.20;

contract ErrorAssumptionOnUnsuccessfulCallOutputPositive {
    function relay(address target, bytes calldata data) external returns (string memory) {
        (bool success, bytes memory returndata) = target.call(data);
        if (!success) {
            bytes4 selector;
            assembly {
                selector := mload(add(returndata, 32))
            }

            if (selector == 0x08c379a0) {
                return abi.decode(_skipSelector(returndata), (string));
            }

            if (selector == 0x4e487b71) {
                uint256 panicCode = abi.decode(_skipSelector(returndata), (uint256));
                return panicCode == 0x11 ? "panic arithmetic" : "panic";
            }

            return "unknown revert";
        }

        return "ok";
    }

    function _skipSelector(bytes memory returndata) private pure returns (bytes memory payload) {
        payload = new bytes(returndata.length - 4);
        for (uint256 i = 4; i < returndata.length; ++i) {
            payload[i - 4] = returndata[i];
        }
    }
}
