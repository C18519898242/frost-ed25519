package frost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const importPartyCount = 3

// ImportPublic is the public data produced by splitting an existing key.
type ImportPublic struct {
	GroupKey ed25519.PublicKey
	Shares   map[party.ID][]byte // Canonical Ristretto encodings of the public shares.
}

// SplitPrivateKey splits a canonical 32-byte little-endian Ed25519 signing
// scalar into three serialized secret shares and their public import data.
// Deliver each secret share only to its intended node over an authenticated,
// confidential channel. The import tool has access to the complete key.
func SplitPrivateKey(privateKey []byte, participants party.IDSlice) (map[party.ID][]byte, *ImportPublic, error) {
	secret, err := ristretto.NewScalar().SetCanonicalBytes(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("frost import: invalid private scalar: %w", err)
	}
	return splitImportScalar(secret, participants)
}

// SplitSeed derives the signing scalar from a 32-byte RFC 8032 Ed25519 seed
// and splits it in the same format as SplitPrivateKey.
func SplitSeed(seed []byte, participants party.IDSlice) (map[party.ID][]byte, *ImportPublic, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("frost import: Ed25519 seed must be 32 bytes")
	}
	digest := sha512.Sum512(seed)
	secret, err := ristretto.NewScalar().SetBytesWithClamping(digest[:32])
	if err != nil {
		return nil, nil, err
	}
	return splitImportScalar(secret, participants)
}

func splitImportScalar(secret *ristretto.Scalar, participants party.IDSlice) (map[party.ID][]byte, *ImportPublic, error) {
	if secret.Equal(ristretto.NewScalar()) == 1 {
		return nil, nil, errors.New("frost import: private scalar is zero")
	}
	if len(participants) != importPartyCount {
		return nil, nil, errors.New("frost import: exactly three participants are required")
	}
	ids := party.NewIDSlice(participants)
	if ids[0] == 0 || ids[0] == ids[1] || ids[1] == ids[2] {
		return nil, nil, errors.New("frost import: participant IDs must be distinct and nonzero")
	}
	poly := polynomial.NewPolynomial(importPartyCount-1, secret)
	defer poly.Reset()
	secrets := make(map[party.ID][]byte, importPartyCount)
	public := &ImportPublic{
		GroupKey: ristretto.NewIdentityElement().ScalarBaseMult(secret).BytesEd25519(),
		Shares:   make(map[party.ID][]byte, importPartyCount),
	}
	for _, id := range ids {
		share := eddsa.NewSecretShare(id, poly.Evaluate(id.Scalar()))
		encoded, err := share.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		secrets[id] = encoded
		public.Shares[id] = share.Public.Bytes()
	}
	// Apply the same public checks before releasing the generated shares.
	if _, err := ImportKey(ids[0], secrets[ids[0]], public.Shares, public.GroupKey); err != nil {
		return nil, nil, fmt.Errorf("frost import: generated invalid sharing: %w", err)
	}
	return secrets, public, nil
}

// ImportKey validates a node's serialized secret share against the three
// public shares and the expected original Ed25519 public key. It returns the
// same signing material as key generation for this node.
func ImportKey(selfID party.ID, secretShare []byte, publicShares map[party.ID][]byte, expectedPublicKey ed25519.PublicKey) (*keygen.Output, error) {
	if len(publicShares) != importPartyCount || selfID == 0 {
		return nil, errors.New("frost import: exactly three participants and a nonzero local ID are required")
	}
	identity := ristretto.NewIdentityElement()
	if len(expectedPublicKey) != ed25519.PublicKeySize || bytes.Equal(expectedPublicKey, identity.BytesEd25519()) {
		return nil, errors.New("frost import: invalid expected Ed25519 public key")
	}
	var secret eddsa.SecretShare
	if err := secret.UnmarshalBinary(secretShare); err != nil {
		return nil, fmt.Errorf("frost import: invalid secret share: %w", err)
	}
	if secret.ID != selfID {
		return nil, errors.New("frost import: secret share belongs to a different participant")
	}
	points := make(map[party.ID]*ristretto.Element, importPartyCount)
	seen := make(map[string]struct{}, importPartyCount)
	for id, encoded := range publicShares {
		if id == 0 {
			return nil, errors.New("frost import: participant ID is zero")
		}
		point, err := new(ristretto.Element).SetCanonicalBytes(encoded)
		if err != nil {
			return nil, fmt.Errorf("frost import: invalid public share for participant %d: %w", id, err)
		}
		if point.Equal(identity) == 1 {
			return nil, fmt.Errorf("frost import: public share for participant %d is the identity", id)
		}
		if bytes.Equal(point.BytesEd25519(), expectedPublicKey) {
			return nil, fmt.Errorf("frost import: public share for participant %d equals the group key", id)
		}
		if _, duplicate := seen[string(encoded)]; duplicate {
			return nil, errors.New("frost import: public shares must be distinct")
		}
		seen[string(encoded)] = struct{}{}
		points[id] = point
	}
	if point := points[selfID]; point == nil || point.Equal(&secret.Public) != 1 {
		return nil, errors.New("frost import: secret share does not match its public share")
	}
	public, err := eddsa.NewPublic(points, importPartyCount-1)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public.GroupKey.ToEd25519(), expectedPublicKey) {
		return nil, errors.New("frost import: public key mismatch")
	}
	// If two points interpolate to the same constant as all three, the
	// sharing polynomial has degree at most one.
	first, second := public.PartyIDs[0], public.PartyIDs[1]
	linear, err := eddsa.NewPublic(map[party.ID]*ristretto.Element{first: points[first], second: points[second]}, 1)
	if err != nil {
		return nil, err
	}
	if public.GroupKey.Equal(linear.GroupKey) {
		return nil, errors.New("frost import: shares do not enforce 3-of-3")
	}
	return &keygen.Output{Public: public, SecretKey: &secret}, nil
}
