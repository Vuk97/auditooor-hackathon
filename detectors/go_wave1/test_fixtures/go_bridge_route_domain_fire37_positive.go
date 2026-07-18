// fixture: positive - bridge proof acceptance omits route and source domains.
package bridge

import "errors"

var ErrBadProof = errors.New("bad proof")

type Context struct{}

type Proof struct {
	Key              []byte
	Nodes            [][]byte
	Root             []byte
	SourceCommitment []byte
	PacketHash       []byte
	ValidatorSetID   uint64
}

type Packet struct {
	MessageID        []byte
	PayloadHash      []byte
	SourceCommitment []byte
}

type Settlement struct {
	PacketHash []byte
	Amount     int64
}

type RootVerifier struct{}

func (RootVerifier) VerifyRoot(root []byte, leaf []byte, nodes [][]byte) bool {
	return true
}

func (RootVerifier) VerifyPacket(packetHash []byte, proof Proof) bool {
	return true
}

type Keeper struct {
	verifier      RootVerifier
	acceptedRoots map[string][]byte
	settlements   map[string]Settlement
}

func (k Keeper) AcceptClientRootWithoutRouteBinding(
	ctx Context,
	routeID string,
	chainID string,
	clientID string,
	validatorSetID uint64,
	receiverDomain string,
	sourceCommitment []byte,
	proof Proof,
) error {
	leaf := HashProofLeaf(proof.Key, proof.Root)
	if !k.verifier.VerifyRoot(proof.Root, leaf, proof.Nodes) {
		return ErrBadProof
	}
	k.acceptedRoots[clientID] = proof.Root
	return nil
}

func (k Keeper) SettlePacketWithoutSourceCommitmentBinding(
	ctx Context,
	routeID string,
	sourceChainID string,
	receiverDomain string,
	sourceCommitment []byte,
	packet Packet,
	proof Proof,
) error {
	packetLeaf := HashPacketLeaf(packet.MessageID, packet.PayloadHash)
	if !k.verifier.VerifyRoot(proof.Root, packetLeaf, proof.Nodes) {
		return ErrBadProof
	}
	k.settlements[routeID] = Settlement{
		PacketHash: packet.PayloadHash,
		Amount:     100,
	}
	return nil
}

func HashProofLeaf(parts ...interface{}) []byte {
	return []byte("leaf")
}

func HashPacketLeaf(parts ...interface{}) []byte {
	return []byte("packet-leaf")
}
