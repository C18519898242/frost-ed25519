package keygen

import (
	"bytes"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *round2) ProcessMessage(msg *messages.Message) *state.Error {
	var computedShareExp ristretto.Element
	computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

	id := msg.From
	shareExp := round.Commitments[id].Evaluate(round.SelfID().Scalar())

	if computedShareExp.Equal(shareExp) != 1 {
		return state.NewError(id, errors.New("VSS failed to validate"))
	}
	round.Secret.Add(&round.Secret, &msg.KeyGen2.Share)

	// We can reset the share in the message now
	msg.KeyGen2.Share.Set(ristretto.NewScalar())

	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *state.Error) {
	groupKey := round.CommitmentsSum.Constant()
	if round.ExpectedKey != nil && !bytes.Equal(groupKey.BytesEd25519(), round.ExpectedKey[:]) {
		return nil, state.NewError(0, errors.New("aggregate Ed25519 public key does not match"))
	}
	shares := make(map[party.ID]*ristretto.Element, round.PartyIDs().N())
	for _, id := range round.PartyIDs() {
		shares[id] = round.CommitmentsSum.Evaluate(id.Scalar())
	}
	if round.ExpectedKey != nil {
		if err := validateContributionShares(round.CommitmentsSum, groupKey, shares); err != nil {
			return nil, state.NewError(0, err)
		}
	}
	round.Output.Public = &eddsa.Public{
		PartyIDs:  round.BaseRound.PartyIDs().Copy(),
		Threshold: round.Threshold,
		Shares:    shares,
		GroupKey:  eddsa.NewPublicKeyFromPoint(groupKey),
	}
	round.Output.SecretKey = eddsa.NewSecretShare(round.SelfID(), &round.Secret)
	return nil, nil
}

func validateContributionShares(commitments *polynomial.Exponent, groupKey *ristretto.Element, shares map[party.ID]*ristretto.Element) error {
	if !commitments.HasFullDegree() {
		return errors.New("aggregate commitment does not enforce 3-of-3")
	}
	identity := ristretto.NewIdentityElement()
	seen := make(map[[32]byte]bool, len(shares))
	for _, share := range shares {
		var encoded [32]byte
		copy(encoded[:], share.Bytes())
		if share.Equal(identity) == 1 || share.Equal(groupKey) == 1 || seen[encoded] {
			return errors.New("degenerate public shares do not enforce 3-of-3")
		}
		seen[encoded] = true
	}
	return nil
}

func (round *round2) NextRound() state.Round {
	return nil
}

func (round *round2) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen2
}
