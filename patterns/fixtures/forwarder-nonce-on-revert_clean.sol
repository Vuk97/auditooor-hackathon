// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ForwarderClean {
    mapping(address => uint256) public nonces;

    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }

    function _recover(ForwardRequest calldata req, bytes calldata sig) internal pure returns (address) {
        sig;
        return req.from;
    }

    function execute(ForwardRequest calldata req, bytes calldata sig)
        external
        payable
        returns (bool, bytes memory)
    {
        address signer = _recover(req, sig);
        require(nonces[signer] == req.nonce, "bad nonce");

        nonces[signer]++;

        (bool success, bytes memory ret) =
            req.to.call{value: req.value, gas: req.gas}(req.data);
        require(success, "inner call failed");
        return (success, ret);
    }
}

contract ForwarderCleanOZ {
    mapping(address => uint256) private _nonces;

    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }

    function _useNonce(address signer) internal returns (uint256 current) {
        current = _nonces[signer];
        _nonces[signer] = current + 1;
    }

    function _recover(ForwardRequest calldata req, bytes calldata sig) internal pure returns (address) {
        sig;
        return req.from;
    }

    function execute(ForwardRequest calldata req, bytes calldata sig)
        external
        payable
        returns (bool, bytes memory)
    {
        address signer = _recover(req, sig);
        require(_useNonce(signer) == req.nonce, "bad nonce");

        (bool success, bytes memory ret) =
            req.to.call{value: req.value, gas: req.gas}(req.data);
        require(success, "inner call failed");
        return (success, ret);
    }
}
