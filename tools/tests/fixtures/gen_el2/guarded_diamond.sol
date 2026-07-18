// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Same diamond facet-map, but WITH the EIP-2535 add-collision reject
// (`require(oldFacetAddress == address(0))`). GEN-EL2 must stay SILENT.
// This is the mutation-verify baseline: remove the require and the screen
// newly fires on addFunction.
contract GuardedDiamond {
    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 position;
    }

    mapping(bytes4 => FacetAddressAndPosition) internal selectorToFacet;
    bytes4[] internal selectors;

    function addFunctions(address _facet, bytes4[] memory _selectors) external {
        require(_facet != address(0), "add: zero facet");
        for (uint256 i; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            address oldFacetAddress = selectorToFacet[selector].facetAddress;
            require(
                oldFacetAddress == address(0),
                "add: function already exists"
            );
            selectorToFacet[selector].facetAddress = _facet;
            selectorToFacet[selector].position = uint96(selectors.length);
            selectors.push(selector);
        }
    }
}
