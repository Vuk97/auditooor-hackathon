// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IPrismaCore {
    function guardian() external view returns (address);
    function setGuardian(address newGuardian) external;
}

contract PrismaCoreMock is IPrismaCore {
    address public override guardian;

    constructor(address initialGuardian) {
        guardian = initialGuardian;
    }

    function setGuardian(address newGuardian) external override {
        guardian = newGuardian;
    }
}

contract AdminVotingFixed {
    struct Action {
        address target;
        bytes data;
    }

    struct Proposal {
        bool processed;
    }

    IPrismaCore public immutable prismaCore;
    Proposal[] internal proposalData;
    mapping(uint256 => Action[]) internal proposalPayloads;

    event ProposalCancelled(uint256 id);

    constructor(IPrismaCore core) {
        prismaCore = core;
        proposalData.push();
        proposalPayloads[0].push(
            Action({
                target: address(core),
                data: abi.encodeWithSelector(IPrismaCore.setGuardian.selector, address(0xBEEF))
            })
        );
        proposalPayloads[0].push(
            Action({
                target: address(this),
                data: abi.encodeWithSignature("sweepTreasury(address,uint256)", msg.sender, 1 ether)
            })
        );
    }

    function cancelProposal(uint256 id) external {
        require(msg.sender == prismaCore.guardian(), "Only guardian can cancel proposals");
        require(id < proposalData.length, "Invalid ID");

        Action[] storage payload = proposalPayloads[id];
        require(!_isSetGuardianPayload(payload.length, payload[0]), "Guardian replacement not cancellable");
        proposalData[id].processed = true;
        emit ProposalCancelled(id);
    }

    function sweepTreasury(address recipient, uint256 amount) external pure returns (address, uint256) {
        return (recipient, amount);
    }

    function _isSetGuardianPayload(uint256 payloadLength, Action memory action) internal view returns (bool) {
        if (payloadLength == 1 && action.target == address(prismaCore)) {
            bytes memory data = action.data;
            bytes4 sig;
            assembly {
                sig := mload(add(data, 0x20))
            }
            return sig == IPrismaCore.setGuardian.selector;
        }
        return false;
    }
}
