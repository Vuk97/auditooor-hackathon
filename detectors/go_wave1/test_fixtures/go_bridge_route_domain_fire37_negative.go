// fixture: negative - proof acceptance binds route, client, receiver, and commitment domains.
package bridge

import "errors"

var ErrBadProof = errors.New("bad proof")
var ErrWrongRoute = errors.New("wrong route")

type Context struct{}

type Proof struct {
	Key              []byte
	Nodes            [][]byte
	Root             []byte
	SourceCommitment []byte
	PacketHash       []byte
	ValidatorSetID   uint64
}

type DecodedProofKey struct {
	RouteID          string
	ChainID          string
	ClientID         string
	ValidatorSetID   uint64
	ReceiverDomain   string
	SourceCommitment []byte
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

type Keeper struct {
	verifier      RootVerifier
	acceptedRoots map[string][]byte
	settlements   map[string]Settlement
}

func (k Keeper) AcceptClientRootWithDomainKey(
	ctx Context,
	routeID string,
	chainID string,
	clientID string,
	validatorSetID uint64,
	receiverDomain string,
	sourceCommitment []byte,
	proof Proof,
) error {
	leaf := BuildBridgeRouteDomainKey(
		routeID,
		chainID,
		clientID,
		validatorSetID,
		receiverDomain,
		sourceCommitment,
		proof.Key,
		proof.Root,
	)
	if !k.verifier.VerifyRoot(proof.Root, leaf, proof.Nodes) {
		return ErrBadProof
	}
	k.acceptedRoots[clientID] = proof.Root
	return nil
}

func (k Keeper) SettlePacketWithDecodedProofKeyChecks(
	ctx Context,
	routeID string,
	sourceChainID string,
	receiverDomain string,
	sourceCommitment []byte,
	packet Packet,
	proof Proof,
) error {
	decoded := DecodeBridgeProofKey(proof.Key)
	if decoded.RouteID != routeID {
		return ErrWrongRoute
	}
	if decoded.ChainID != sourceChainID {
		return ErrWrongRoute
	}
	if decoded.ReceiverDomain != receiverDomain {
		return ErrWrongRoute
	}
	if !BytesEqual(decoded.SourceCommitment, sourceCommitment) {
		return ErrWrongRoute
	}
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

func BuildBridgeRouteDomainKey(parts ...interface{}) []byte {
	return []byte("domain-key")
}

func DecodeBridgeProofKey(raw []byte) DecodedProofKey {
	return DecodedProofKey{}
}

func HashPacketLeaf(parts ...interface{}) []byte {
	return []byte("packet-leaf")
}

func BytesEqual(left []byte, right []byte) bool {
	return true
}
