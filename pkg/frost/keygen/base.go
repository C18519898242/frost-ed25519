package keygen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type (
	round0 struct {
		*state.BaseRound

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold party.Size

		// Secret is first set to the zero coefficient of the polynomial we send to the other parties.
		// Once all received shares are declared, they are summed here to produce the party's
		// final secret key.
		Secret ristretto.Scalar

		// ExpectedKey is set for DKG with a supplied local contribution.
		ExpectedKey  *[ed25519.PublicKeySize]byte
		ProofContext [sha256.Size]byte

		// Polynomial used to sample shares
		Polynomial *polynomial.Polynomial

		// CommitmentsSum is the sum of all commitments, we use it to compute public key shares
		CommitmentsSum *polynomial.Exponent

		// Commitments contains all other parties commitment polynomials
		Commitments map[party.ID]*polynomial.Exponent

		Output *Output
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

func NewRound(selfID party.ID, partyIDs party.IDSlice, threshold party.Size) (state.Round, *Output, error) {
	return newRound(selfID, partyIDs, threshold)
}

// NewRoundWithContribution builds the first round of a 3-of-3 DKG with a supplied scalar.
func NewRoundWithContribution(selfID party.ID, partyIDs party.IDSlice, contribution []byte, expectedPublicKey ed25519.PublicKey, sessionID []byte) (state.Round, *Output, error) {
	if len(partyIDs) != 3 || len(sessionID) == 0 {
		return nil, nil, errors.New("contribution DKG requires three participants and a session ID")
	}
	ids := party.NewIDSlice(partyIDs)
	if ids[0] == 0 || ids[0] == ids[1] || ids[1] == ids[2] {
		return nil, nil, errors.New("participant IDs must be distinct and nonzero")
	}
	var expected [ed25519.PublicKeySize]byte
	if len(expectedPublicKey) != len(expected) || bytes.Equal(expectedPublicKey, expected[:]) ||
		bytes.Equal(expectedPublicKey, ristretto.NewIdentityElement().BytesEd25519()) {
		return nil, nil, errors.New("invalid expected Ed25519 public key")
	}
	copy(expected[:], expectedPublicKey)
	r, output, err := newRound(selfID, ids, 2)
	if err != nil {
		return nil, nil, err
	}
	if _, err := r.Secret.SetCanonicalBytes(contribution); err != nil || r.Secret.Equal(ristretto.NewScalar()) == 1 {
		return nil, nil, errors.New("contribution must be a canonical nonzero Ed25519 scalar")
	}
	r.ExpectedKey = &expected
	h := sha256.New()
	h.Write([]byte("frost-ed25519/contribution-dkg/v1"))
	h.Write(expected[:])
	for _, id := range ids {
		h.Write(id.Bytes())
	}
	h.Write(sessionID)
	h.Sum(r.ProofContext[:0])
	return r, output, nil
}

func newRound(selfID party.ID, partyIDs party.IDSlice, threshold party.Size) (*round0, *Output, error) {
	N := partyIDs.N()

	if threshold == 0 {
		return nil, nil, errors.New("threshold must be at least 1, or a minimum of T+1=2 signers")
	}
	if threshold > N-1 {
		return nil, nil, errors.New("threshold must be at most N-1, or a maximum of T+1=N signers")
	}

	baseRound, err := state.NewBaseRound(selfID, partyIDs)
	if err != nil {
		return nil, nil, err
	}

	r := round0{
		BaseRound:   baseRound,
		Threshold:   threshold,
		Commitments: make(map[party.ID]*polynomial.Exponent, N),
		Output:      &Output{},
	}

	return &r, r.Output, nil
}

func (round *round0) Reset() {
	round.Secret.Set(ristretto.NewScalar())
	if round.Polynomial != nil {
		round.Polynomial.Reset()
	}
	if round.CommitmentsSum != nil {
		round.CommitmentsSum.Reset()
	}
	for _, p := range round.Commitments {
		p.Reset()
	}
	round.Output = nil
}

// ---
// Messages
// ---

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{messages.MessageTypeNone, messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
}
