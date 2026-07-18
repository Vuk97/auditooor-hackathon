// SPDX-License-Identifier: MIT
// Fixture: erc1155-batch-length-mismatch-allows-partial — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

contract Erc1155BatchLenMismatchVuln {
    // token id => owner => balance
    mapping(uint256 => mapping(address => uint256)) internal _balances;

    event TransferBatch(address operator, address from, address to, uint256[] ids, uint256[] amounts);

    // VULN #1: mintBatch — no length equality check. OOB panic when
    // amounts is shorter than ids; silent drift when post-emit hooks use
    // amounts.length while the loop uses ids.length.
    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
    }

    // VULN #2: burnBatch — same shape, no guard. Partial-burn risk where
    // the emitted event claims a full burn.
    function burnBatch(address from, uint256[] calldata ids, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < amounts.length; i++) {
            _balances[ids[i]][from] -= amounts[i];
        }
        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
    }

    // VULN #3: internal _batchMint used by other surfaces. No require.
    function _batchMint(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }
    }

    // VULN #4: _safeBatchTransferFrom override missing the parent-class
    // length check. Classic OZ-fork bug.
    function _safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts
    ) external {
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][from] -= amounts[i];
            _balances[ids[i]][to] += amounts[i];
        }
    }

    // VULN #5: batchTransfer with a guard on the WRONG invariant
    // (ids.length > 0 is not enough — mismatch still possible).
    function batchTransfer(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts
    ) external {
        require(ids.length > 0, "empty batch");
        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][from] -= amounts[i];
            _balances[ids[i]][to] += amounts[i];
        }
    }
}
