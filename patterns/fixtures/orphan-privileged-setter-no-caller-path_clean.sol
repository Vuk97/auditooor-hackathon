// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// SAFE: `Vader.changeDAO` is still `onlyDAO`, but the DAO contract exposes
// a dedicated `rotateDAO` governance action that invokes
// `vader.changeDAO(newDAO)`. The setter therefore has a reachable caller
// path from the authorized side — admin rotation is live, emergency
// recovery is possible.
interface IVader {
    function changeDAO(address newDAO) external;
}

contract VaderSafe {
    address public DAO;

    constructor(address dao_) {
        DAO = dao_;
    }

    modifier onlyDAO() {
        require(msg.sender == DAO, "!DAO");
        _;
    }

    function changeDAO(address newDAO) external onlyDAO {
        DAO = newDAO;
    }
}

contract DAOSafe {
    IVader public immutable vader;
    address public governor;

    constructor(IVader vader_, address governor_) {
        vader = vader_;
        governor = governor_;
    }

    modifier onlyGovernor() {
        require(msg.sender == governor, "!governor");
        _;
    }

    // Reachable caller-path: the DAO contract actually calls Vader.changeDAO,
    // so the privileged setter is not orphan.
    function rotateDAO(address newDAO) external onlyGovernor {
        vader.changeDAO(newDAO);
    }
}
