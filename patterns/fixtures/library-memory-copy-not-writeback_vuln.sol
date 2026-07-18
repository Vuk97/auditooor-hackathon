// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MapLib {
    struct Map { uint256[] values; }
    function insert(Map memory m, uint256 v) internal pure returns (Map memory) {
        uint256[] memory newVals = new uint256[](m.values.length + 1);
        for (uint i = 0; i < m.values.length; i++) newVals[i] = m.values[i];
        newVals[m.values.length] = v;
        m.values = newVals;
        return m;
    }
}

contract LibraryMemoryCopyNotWritebackVuln {
    using MapLib for MapLib.Map;
    MapLib.Map internal state;

    function addValue(uint256 v) external {
        MapLib.Map memory local = state;
        // VULN: return value discarded — state never updated.
        local.insert(v);
    }

    function count() external view returns (uint256) {
        return state.values.length;
    }
}
