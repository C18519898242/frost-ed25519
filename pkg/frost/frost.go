package frost

import (
	"crypto/ed25519"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// NewKeygenState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewKeygenState(selfID party.ID, partyIDs party.IDSlice, threshold party.Size, timeout time.Duration) (*state.State, *keygen.Output, error) {
	round, output, err := keygen.NewRound(selfID, partyIDs, threshold)
	if err != nil {
		return nil, nil, err
	}
	s, err := state.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}

	return s, output, nil
}

// NewKeygenStateWithContribution starts a 3-of-3 DKG using one node's canonical,
// nonzero 32-byte little-endian scalar. The scalar is copied into the round.
// All nodes must agree on the expected aggregate Ed25519 public key and a unique,
// nonempty session ID. Route messages over authenticated, confidential channels
// bound to that session, with reliable broadcast for broadcast messages.
func NewKeygenStateWithContribution(selfID party.ID, partyIDs party.IDSlice, contribution []byte, expectedPublicKey ed25519.PublicKey, sessionID []byte, timeout time.Duration) (*state.State, *keygen.Output, error) {
	round, output, err := keygen.NewRoundWithContribution(selfID, partyIDs, contribution, expectedPublicKey, sessionID)
	if err != nil {
		return nil, nil, err
	}
	s, err := state.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}
	return s, output, nil
}

// NewSignState returns a state.State which coordinates the multiple rounds.
// partyIDs must contain sorted, distinct, nonzero IDs.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewSignState(partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte, timeout time.Duration) (*state.State, *sign.Output, error) {
	round, output, err := sign.NewRound(partyIDs, secret, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s, err := state.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}

	return s, output, nil
}
