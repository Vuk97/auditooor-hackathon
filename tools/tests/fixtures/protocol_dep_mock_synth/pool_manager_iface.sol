// Fixture: a pool-manager getter + permission-gate shape (docstring anchor: a
// Maple-style PoolManager). totalAssets() is a plain settable getter (drive it
// for an inflation/share-price exploit); canCall(...) is a multi-return
// permission gate the target checks before an action; the synthesizer backs the
// gate with a safe-default stub. Generic SHAPE, no target literal in logic.
interface IPoolMgr {
    function totalAssets() external view returns (uint256);
    function canCall(bytes32 functionId, address caller, bytes calldata data)
        external view returns (bool canCall_, string memory errorMessage_);
    function setActive(bool active) external;
}
