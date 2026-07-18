// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Client {
    struct EVM2AnyMessage {
        bytes receiver;
        bytes data;
        bytes tokenAmounts;
        bytes extraArgs;
        address feeToken;
    }
}

interface ICCIPRouter {
    function ccipSend(uint64 destinationChainSelector, Client.EVM2AnyMessage calldata message)
        external
        payable
        returns (bytes32 messageId);
}

contract CcipRafflePropagationClean {
    struct Raffle {
        address winner;
        bool propagated;
    }

    ICCIPRouter public immutable router;
    mapping(uint256 => Raffle) public raffles;
    mapping(uint64 => address) public expectedDestination;

    constructor(ICCIPRouter ccipRouter) {
        router = ccipRouter;
    }

    function configureDestination(uint64 chainSelector, address prizeManager) external {
        expectedDestination[chainSelector] = prizeManager;
    }

    function recordWinner(uint256 raffleId, address winner) external {
        raffles[raffleId] = Raffle({winner: winner, propagated: false});
    }

    function propagateRaffleWinner(
        address prizeManager,
        uint64 chainSelector,
        uint256 raffleId
    ) external payable {
        Raffle storage raffle = raffles[raffleId];
        require(!raffle.propagated, "already propagated");
        require(expectedDestination[chainSelector] == prizeManager, "bad destination");

        Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
            receiver: abi.encode(prizeManager),
            data: abi.encode(raffleId, raffle.winner),
            tokenAmounts: "",
            extraArgs: "",
            feeToken: address(0)
        });

        router.ccipSend{value: msg.value}(chainSelector, message);
        raffle.propagated = true;
    }
}
