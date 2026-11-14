package eddsa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const derivationDomain = "mpc-frost-ed25519/v1"

// DefaultChainCode derives a public root chain code for keys created without one.
func (pk *PublicKey) DefaultChainCode() [32]byte {
	return sha256.Sum256(append([]byte(derivationDomain+"/root"), pk.ToEd25519()...))
}

// ValidatePath accepts only non-hardened indices.
func ValidatePath(path []uint32) error {
	for _, index := range path {
		if index >= 1<<31 {
			return errors.New("hardened FROST derivation is unsupported")
		}
	}
	return nil
}

// Derive returns the verification key and chain code at a non-hardened path.
func (pk *PublicKey) Derive(chainCode [32]byte, path []uint32) (*PublicKey, [32]byte, error) {
	child, chainCode, _, err := pk.derive(chainCode, path)
	return child, chainCode, err
}

// DeriveSigningScalar derives the scalar and chain code for offline signing.
// The input and output are canonical little-endian signing scalars.
func DeriveSigningScalar(root [32]byte, chainCode [32]byte, path []uint32) ([32]byte, [32]byte, error) {
	scalar, err := ristretto.NewScalar().SetCanonicalBytes(root[:])
	if err != nil || scalar.Equal(ristretto.NewScalar()) == 1 {
		return [32]byte{}, [32]byte{}, errors.New("invalid Ed25519 signing scalar")
	}
	key := NewPublicKeyFromPoint(ristretto.NewIdentityElement().ScalarBaseMult(scalar))
	_, childCode, tweak, err := key.derive(chainCode, path)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var child [32]byte
	copy(child[:], scalar.Add(scalar, tweak).Bytes())
	return child, childCode, nil
}

// DeriveShare returns a new local share and public data for the same path.
func (p *Public) DeriveShare(share *SecretShare, chainCode [32]byte, path []uint32) (*SecretShare, *Public, error) {
	if p == nil || p.GroupKey == nil || share == nil {
		return nil, nil, errors.New("FROST share and public data are required")
	}
	parentPoint := p.Shares[share.ID]
	if parentPoint == nil || parentPoint.Equal(&share.Public) != 1 {
		return nil, nil, errors.New("FROST secret share does not match public data")
	}
	key, _, tweak, err := p.GroupKey.derive(chainCode, path)
	if err != nil {
		return nil, nil, err
	}
	tweakPoint := ristretto.NewIdentityElement().ScalarBaseMult(tweak)
	points := make(map[party.ID]*ristretto.Element, len(p.Shares))
	for id, point := range p.Shares {
		if point == nil {
			return nil, nil, errors.New("missing FROST public share")
		}
		points[id] = ristretto.NewIdentityElement().Add(point, tweakPoint)
	}
	child := NewSecretShare(share.ID, ristretto.NewScalar().Add(&share.Secret, tweak))
	return child, &Public{
		PartyIDs: p.PartyIDs.Copy(), Threshold: p.Threshold, Shares: points, GroupKey: key,
	}, nil
}

func (pk *PublicKey) derive(chainCode [32]byte, path []uint32) (*PublicKey, [32]byte, *ristretto.Scalar, error) {
	if err := ValidatePath(path); err != nil {
		return nil, [32]byte{}, nil, err
	}
	identity := ristretto.NewIdentityElement()
	if pk == nil || pk.pk.Equal(identity) == 1 {
		return nil, [32]byte{}, nil, errors.New("invalid FROST parent public key")
	}
	child := NewPublicKeyFromPoint(&pk.pk)
	total := ristretto.NewScalar()
	for _, index := range path {
		var encodedIndex [4]byte
		binary.BigEndian.PutUint32(encodedIndex[:], index)
		input := append(child.ToEd25519(), encodedIndex[:]...)
		h := hmac.New(sha512.New, chainCode[:])
		h.Write([]byte(derivationDomain + "/tweak"))
		h.Write(input)
		tweak, err := ristretto.NewScalar().SetUniformBytes(h.Sum(nil))
		if err != nil {
			return nil, [32]byte{}, nil, err
		}
		child.pk.Add(&child.pk, ristretto.NewIdentityElement().ScalarBaseMult(tweak))
		if child.pk.Equal(identity) == 1 || tweak.Equal(ristretto.NewScalar()) == 1 {
			return nil, [32]byte{}, nil, errors.New("invalid FROST child key")
		}
		total.Add(total, tweak)
		h.Reset()
		h.Write([]byte(derivationDomain + "/chain"))
		h.Write(input)
		copy(chainCode[:], h.Sum(nil))
	}
	return child, chainCode, total, nil
}
