// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A diamond facet-selector map registered with NO add-collision reject.
// GEN-EL2 must FIRE: selectorToFacet[sel] = facet in an ADD loop with no
// `require(oldFacetAddress == address(0))` guard -> a re-added selector
// last-wins and shadows the prior facet.
contract FireDiamond {
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
            // NO collision reject on selectorToFacet[selector] before writing.
            selectorToFacet[selector].facetAddress = _facet;
            selectorToFacet[selector].position = uint96(selectors.length);
            selectors.push(selector);
        }
    }
}
