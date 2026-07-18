pragma solidity ^0.8.20;

contract PendingSiloNativeAssetMintClean {
    function depositEth(address controller) external payable {
        controller;
    }
}

contract NativeAssetMintWithoutMsgvalueEqualityCheckClean {
    struct EpochData {
        mapping(address => uint256) depositRequest;
        uint256 totalDepositAssets;
    }

    PendingSiloNativeAssetMintClean public pendingSilo;
    mapping(uint256 => EpochData) internal epochs;
    uint256 internal currentEpoch;
    address public wrappedNativeToken;

    constructor(PendingSiloNativeAssetMintClean silo, address wrapped) {
        pendingSilo = silo;
        wrappedNativeToken = wrapped;
    }

    function requestDeposit(
        uint256 assets,
        address controller,
        address owner
    ) external payable returns (uint256 requestId) {
        if (msg.value > 0) {
            require(assets == msg.value, "native/assets mismatch");
            pendingSilo.depositEth{value: msg.value}(controller);
        }

        epochs[currentEpoch].depositRequest[controller] += assets;
        epochs[currentEpoch].totalDepositAssets += assets;
        requestId = owner == controller ? currentEpoch + 1 : currentEpoch + 2;
    }
}
