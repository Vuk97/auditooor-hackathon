// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

library ILiFi {
    struct BridgeData {
        bytes32 transactionId;
        address receiver;
        address sendingAssetId;
        uint256 minAmount;
        uint256 destinationChainId;
        bool hasSourceSwaps;
        bool hasDestinationCall;
    }
}

contract LiFiPackedEndpointValidatorClean {
    error InvalidSelector();
    error UnsupportedPackedEndpoint();

    function validateTxData(bytes calldata txData) external pure returns (address receiver, uint256 minAmount) {
        if (txData.length < 4) {
            revert InvalidSelector();
        }

        bytes4 selector = bytes4(txData[:4]);
        if (_isPackedEndpoint(selector)) {
            revert UnsupportedPackedEndpoint();
        }

        if (selector == this.startBridgeTokensViaGeneric.selector) {
            ILiFi.BridgeData memory bridgeData = abi.decode(txData[4:], (ILiFi.BridgeData));
            return (bridgeData.receiver, bridgeData.minAmount);
        }

        revert InvalidSelector();
    }

    function _isPackedEndpoint(bytes4 selector) private pure returns (bool) {
        return selector == this.startBridgeTokensViaHopL2NativePacked.selector
            || selector == this.startBridgeTokensViaCBridgeNativePacked.selector;
    }

    function startBridgeTokensViaGeneric(ILiFi.BridgeData calldata bridgeData)
        external
        pure
        returns (address, uint256)
    {
        return (bridgeData.receiver, bridgeData.minAmount);
    }

    function startBridgeTokensViaHopL2NativePacked(
        bytes32 transactionId,
        address receiver,
        uint256 amount,
        uint256 destinationChainId
    ) external pure returns (bytes32, address, uint256, uint256) {
        return (transactionId, receiver, amount, destinationChainId);
    }

    function startBridgeTokensViaCBridgeNativePacked(
        bytes32 transactionId,
        address receiver,
        uint256 amount,
        uint64 destinationChainId
    ) external pure returns (bytes32, address, uint256, uint64) {
        return (transactionId, receiver, amount, destinationChainId);
    }
}
