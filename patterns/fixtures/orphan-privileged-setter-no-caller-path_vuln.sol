// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// BUG: `Vader.changeDAO` is `onlyDAO`, meaning only the DAO contract can call
// it. But the DAO contract below has NO function that ever invokes
// `vader.changeDAO(...)`. The setter is therefore orphan / unreachable — the
// DAO address can never be rotated. This bricks emergency recovery and admin
// migration. Solodit #3906 (Vader Protocol).
contract Vader {
    address public DAO;

    constructor(address dao_) {
        DAO = dao_;
    }

    modifier onlyDAO() {
        require(msg.sender == DAO, "!DAO");
        _;
    }

    // Orphan: only DAO can call, but DAO has no caller-path to here.
    function changeDAO(address newDAO) external onlyDAO {
        DAO = newDAO;
    }
}

contract DAO {
    // Generic proposal surface — but nothing here ever routes a call to
    // `Vader.changeDAO(...)`. Reviewer: search cross-contract for any
    // invocation of `changeDAO` originating from the authorized side.
    function proposeAction(address target, bytes calldata data) external {
        // abstract governance surface; no specialization that reaches
        // Vader.changeDAO — the setter is stranded.
    }

    function execute(address target, bytes calldata data) external {
        // arbitrary execution would let DAO reach Vader.changeDAO in theory,
        // but this fixture mirrors the real Vader DAO which had *no* such
        // generic execute path and no specific changeDAO wrapper either.
        revert("unimplemented");
    }
}
