package keygen

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *round1) ProcessMessage(msg *messages.Message) *state.Error {
	from := msg.From
	if msg.KeyGen1.Commitments.Degree() != round.Threshold {
		return state.NewError(from, errors.New("unexpected commitment degree"))
	}
	public := msg.KeyGen1.Commitments.Constant()
	if round.ExpectedKey != nil && public.Equal(ristretto.NewIdentityElement()) == 1 {
		return state.NewError(from, errors.New("zero public contribution"))
	}
	if !msg.KeyGen1.Proof.Verify(from, public, round.ProofContext[:]) {
		return state.NewError(from, errors.New("ZK Schnorr failed"))
	}

	round.Commitments[from] = msg.KeyGen1.Commitments

	// Add the commitments to our own, so that we can interpolate the final polynomial
	if err := round.CommitmentsSum.Add(msg.KeyGen1.Commitments); err != nil {
		return state.NewError(from, err)
	}
	return nil
}

func (round *round1) GenerateMessages() ([]*messages.Message, *state.Error) {
	msgsOut := make([]*messages.Message, 0, len(round.PartyIDs())-1)
	for _, id := range round.PartyIDs() {
		if id == round.SelfID() {
			continue
		}
		msgsOut = append(msgsOut, messages.NewKeyGen2(round.SelfID(), id, round.Polynomial.Evaluate(id.Scalar())))
	}

	// Now that we have received the commitment from every one,
	// we no longer require the original polynomial, so we reset it
	round.Polynomial.Reset()

	return msgsOut, nil
}

func (round *round1) NextRound() state.Round {
	return &round2{round}
}

func (round *round1) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen1
}
