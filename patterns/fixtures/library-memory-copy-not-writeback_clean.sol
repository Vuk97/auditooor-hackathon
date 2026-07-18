// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MapLib {
    struct Map { uint256[] values; }
    function insertStorage(Map storage m, uint256 v) internal {
        m.values.push(v);
    }
}

contract LibraryMemoryCopyNotWritebackClean {
    using MapLib for MapLib.Map;
    MapLib.Map internal state;

    function addValue(uint256 v) external {
        // CLEAN: library operates on storage reference; mutation persists.
        state.insertStorage(v);
    }

    function count() external view returns (uint256) {
        return state.values.length;
    }
}
