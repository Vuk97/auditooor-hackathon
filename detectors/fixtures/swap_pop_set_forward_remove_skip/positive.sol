// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MiniSet {
    struct AddressSet {
        address[] values;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set.values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return set.values[index];
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        for (uint256 i = 0; i < set.values.length; i++) {
            if (set.values[i] == value) {
                set.values[i] = set.values[set.values.length - 1];
                set.values.pop();
                return true;
            }
        }
        return false;
    }
}

contract SwapPopForwardRemovePositive {
    using MiniSet for MiniSet.AddressSet;

    MiniSet.AddressSet private blocked;
    mapping(address => uint256) public expiresAt;

    function sweepExpired() external {
        for (uint256 i = 0; i < blocked.length(); i++) {
            address account = blocked.at(i);
            if (expiresAt[account] < block.timestamp) {
                blocked.remove(account);
            }
        }
    }
}
