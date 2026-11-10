package frost_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestImportKeySignsWithOriginalKey(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	seed := bytes.Repeat([]byte{42}, ed25519.SeedSize)
	expected := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	digest := sha512.Sum512(seed)
	scalar, err := ristretto.NewScalar().SetBytesWithClamping(digest[:32])
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		split func() (map[party.ID][]byte, *frost.ImportPublic, error)
	}{
		{"seed", func() (map[party.ID][]byte, *frost.ImportPublic, error) { return frost.SplitSeed(seed, ids) }},
		{"scalar", func() (map[party.ID][]byte, *frost.ImportPublic, error) {
			return frost.SplitPrivateKey(scalar.Bytes(), ids)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares, public, err := tc.split()
			require.NoError(t, err)
			require.Equal(t, expected, public.GroupKey)

			message := []byte("sign with imported key")
			states := make([]*state.State, 0, len(ids))
			outputs := make([]*sign.Output, 0, len(ids))
			for _, id := range ids {
				cfg, err := frost.ImportKey(id, shares[id], public.Shares, expected)
				require.NoError(t, err)
				require.Equal(t, expected, cfg.Public.GroupKey.ToEd25519())
				if id == ids[0] {
					_, _, err := frost.NewSignState(ids[:2], cfg.SecretKey, cfg.Public, message, 0)
					require.Error(t, err)
					_, _, err = frost.NewSignState(party.IDSlice{1, 1, 2}, cfg.SecretKey, cfg.Public, message, 0)
					require.Error(t, err)
				}
				s, out, err := frost.NewSignState(ids, cfg.SecretKey, cfg.Public, message, 0)
				require.NoError(t, err)
				states = append(states, s)
				outputs = append(outputs, out)
			}

			var incoming [][]byte
			for round := 0; round < 3; round++ {
				var outgoing [][]byte
				for _, s := range states {
					messages, err := helpers.PartyRoutine(incoming, s)
					require.NoError(t, err)
					outgoing = append(outgoing, messages...)
				}
				incoming = outgoing
			}
			for _, out := range outputs {
				require.NotNil(t, out.Signature)
				require.True(t, ed25519.Verify(expected, message, out.Signature.ToEd25519()))
			}
		})
	}
}

func TestImportKeyRejectsInvalidShares(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	shares, public, err := frost.SplitSeed(make([]byte, ed25519.SeedSize), ids)
	require.NoError(t, err)
	_, err = frost.ImportKey(2, shares[1], public.Shares, public.GroupKey)
	require.Error(t, err)
	_, err = frost.ImportKey(1, shares[1], public.Shares, make(ed25519.PublicKey, ed25519.PublicKeySize))
	require.Error(t, err)
	public.Shares[3] = []byte{1}
	_, err = frost.ImportKey(1, shares[1], public.Shares, public.GroupKey)
	require.Error(t, err)
}

func TestImportKeyRejectsTwoOfThreeSharing(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	_, shares := helpers.GenerateSecrets(ids, 1)
	public := helpers.GeneratePublic(1, shares)
	points := make(map[party.ID][]byte, len(ids))
	for _, id := range ids {
		points[id] = public.Shares[id].Bytes()
	}
	encoded, err := shares[1].MarshalBinary()
	require.NoError(t, err)
	_, err = frost.ImportKey(1, encoded, points, public.GroupKey.ToEd25519())
	require.Error(t, err)
}

func TestImportKeyRejectsDegenerateQuadraticSharing(t *testing.T) {
	expected := ristretto.NewIdentityElement().ScalarBaseMult(party.ID(5).Scalar()).BytesEd25519()
	for _, tc := range []struct {
		name   string
		values [3]party.ID
	}{
		{"share equals group key", [3]party.ID{5, 7, 11}}, // f(x) = 5 + x(x-1)
		{"duplicate shares", [3]party.ID{2, 1, 2}},        // f(x) = 5 + x(x-4)
	} {
		t.Run(tc.name, func(t *testing.T) {
			points := make(map[party.ID][]byte, 3)
			var ownShare []byte
			for i, value := range tc.values {
				id := party.ID(i + 1)
				share := eddsa.NewSecretShare(id, value.Scalar())
				points[id] = share.Public.Bytes()
				if id == 1 {
					var err error
					ownShare, err = share.MarshalBinary()
					require.NoError(t, err)
				}
			}
			_, err := frost.ImportKey(1, ownShare, points, expected)
			require.Error(t, err)
		})
	}
}

func TestSplitPrivateKeyRejectsInvalidInput(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	for _, raw := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} {
		_, _, err := frost.SplitPrivateKey(raw, ids)
		require.Error(t, err)
	}
	for _, invalid := range []party.IDSlice{ids[:2], {1, 1, 3}, {0, 2, 3}} {
		_, _, err := frost.SplitSeed(make([]byte, ed25519.SeedSize), invalid)
		require.Error(t, err)
	}
	_, _, err := frost.SplitSeed(make([]byte, ed25519.PrivateKeySize), ids)
	require.Error(t, err)
}
