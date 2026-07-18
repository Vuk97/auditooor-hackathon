package fixtures

import (
	"crypto/ed25519"
	"crypto/sha256"
)

type Hash32 [32]byte

type TransferRequest struct {
	PayloadHash Hash32
	Recipient   Hash32
	Amount      uint64
}

type SignatureShare []byte

type Keeper struct {
	executedSessions map[Hash32]bool
	claimedMessages  map[Hash32]bool
	finalizedRounds   map[Hash32]bool
	groupKey          BlsGroupKey
}

type BlsGroupKey struct{}

func (BlsGroupKey) FastAggregateVerify(_ [][]byte, _ []byte, _ []byte) bool {
	return true
}

type FrostTranscript struct{}

func NewFrostTranscript(_ string) *FrostTranscript {
	return &FrostTranscript{}
}

func (t *FrostTranscript) AppendBytes(_ string, _ []byte) {}

func (t *FrostTranscript) AppendUint64(_ string, _ uint64) {}

func (t *FrostTranscript) Challenge(_ string) []byte {
	return []byte("challenge")
}

func (k *Keeper) releaseFunds(_ Hash32, _ uint64) error {
	return nil
}

func (k *Keeper) ExecuteEd25519Intent(
	chainID string,
	domainSeparator Hash32,
	sessionID Hash32,
	signerRole string,
	purpose string,
	req TransferRequest,
	pub ed25519.PublicKey,
	sig []byte,
) error {
	_ = chainID
	_ = domainSeparator
	_ = signerRole
	_ = purpose

	signedBytes := make([]byte, 0, 96)
	signedBytes = append(signedBytes, req.PayloadHash[:]...)
	signedBytes = append(signedBytes, req.Recipient[:]...)
	digest := sha256.Sum256(signedBytes)

	if !ed25519.Verify(pub, digest[:], sig) {
		return errBadSignature
	}

	k.executedSessions[sessionID] = true
	return k.releaseFunds(req.Recipient, req.Amount)
}

func (k *Keeper) ClaimSecp256K1Authorization(
	chainID uint64,
	participantSetHash Hash32,
	purpose string,
	req TransferRequest,
	pubkey []byte,
	sig []byte,
) bool {
	_ = chainID
	_ = participantSetHash
	_ = purpose

	messageBytes := make([]byte, 0, 96)
	messageBytes = append(messageBytes, req.PayloadHash[:]...)
	messageBytes = append(messageBytes, req.Recipient[:]...)
	digest := sha256.Sum256(messageBytes)

	if !secp256k1.VerifySignature(pubkey, digest[:], sig) {
		return false
	}

	k.claimedMessages[req.PayloadHash] = true
	_ = k.releaseFunds(req.Recipient, req.Amount)
	return true
}

func (k *Keeper) SettleBLSAggregateAuthorization(
	chainID uint64,
	domainSeparator Hash32,
	sessionID Hash32,
	participantSetHash Hash32,
	req TransferRequest,
	publicKeys [][]byte,
	aggregateSignature []byte,
) error {
	_ = chainID
	_ = domainSeparator
	_ = participantSetHash

	transcript := NewFrostTranscript("bls-settlement")
	transcript.AppendBytes("payload", req.PayloadHash[:])
	transcript.AppendBytes("recipient", req.Recipient[:])
	transcript.AppendUint64("amount", req.Amount)
	challenge := transcript.Challenge("bls-auth")

	if !k.groupKey.FastAggregateVerify(publicKeys, challenge, aggregateSignature) {
		return errBadSignature
	}

	k.executedSessions[sessionID] = true
	return k.releaseFunds(req.Recipient, req.Amount)
}

func (k *Keeper) FinalizeFrostShareAuthorization(
	chainID uint64,
	domainSeparator Hash32,
	signingRound uint64,
	signerRole string,
	participantSetHash Hash32,
	purpose string,
	req TransferRequest,
	share SignatureShare,
	publicKey []byte,
) error {
	_ = chainID
	_ = domainSeparator
	_ = signingRound
	_ = signerRole
	_ = purpose

	transcript := NewFrostTranscript("frost-key-tweak")
	transcript.AppendBytes("payload", req.PayloadHash[:])
	transcript.AppendBytes("recipient", req.Recipient[:])
	transcript.AppendUint64("amount", req.Amount)
	challenge := transcript.Challenge("frost-share")

	if !frost.VerifySignatureShare(publicKey, challenge, share) {
		return errBadSignature
	}

	k.finalizedRounds[participantSetHash] = true
	return k.releaseFunds(req.Recipient, req.Amount)
}

var errBadSignature = errorString("bad signature")

type errorString string

func (e errorString) Error() string {
	return string(e)
}
