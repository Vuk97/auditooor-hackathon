// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// Transitive-binding FP guard: _origin reaches the digest INDIRECTLY through the
// local _domainHash = domainHash(_origin, _hook). The backward def-use slice must
// credit _origin as bound -> clean (0 rows). A naive direct-token check FPs here.
library DigestTransitive {
    function domainHash(uint32 _origin, bytes32 _hook)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(_origin, _hook, "X"));
    }

    function digest(
        uint32 _origin,
        bytes32 _hook,
        uint32 _nonce,
        bytes32 _root
    ) internal pure returns (bytes32) {
        bytes32 _domainHash = domainHash(_origin, _hook);
        return keccak256(abi.encodePacked(_domainHash, _nonce, _root));
    }
}
