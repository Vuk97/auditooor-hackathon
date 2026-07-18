// SPDX-License-Identifier: MIT
// Fixture: erc1155-batch-length-mismatch-allows-partial — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

contract Erc1155BatchLenMismatchClean {
    mapping(uint256 => mapping(address => uint256)) internal _balances;

    event TransferBatch(address operator, address from, address to, uint256[] ids, uint256[] amounts);

    // CLEAN #1: canonical require(ids.length == amounts.length).
    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(ids.length == amounts.length, "ERC1155: array length mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
    }

    // CLEAN #2: same guard, reversed argument order — also accepted.
    function burnBatch(address from, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(amounts.length == ids.length, "length mismatch");
        for (uint256 i = 0; i < amounts.length; i++) {
            _balances[ids[i]][from] -= amounts[i];
        }
        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
    }

    // CLEAN #3: _batchMint with the require.
    function _batchMint(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(ids.length == amounts.length, "mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }
    }

    // CLEAN #4: _safeBatchTransferFrom with guard.
    function _safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts
    ) external {
        require(ids.length == amounts.length, "ERC1155: array length mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][from] -= amounts[i];
            _balances[ids[i]][to] += amounts[i];
        }
    }
}
