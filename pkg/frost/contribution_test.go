package frost_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestKeygenWithContribution(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	var contributions [3][32]byte
	total := ristretto.NewScalar()
	for i := range contributions {
		contributions[i][0] = byte(i + 1)
		s, err := ristretto.NewScalar().SetCanonicalBytes(contributions[i][:])
		require.NoError(t, err)
		total.Add(total, s)
	}
	expected := ed25519.PublicKey(ristretto.NewIdentityElement().ScalarBaseMult(total).BytesEd25519())
	session := []byte("contribution-test")
	_, _, err := frost.NewKeygenStateWithContribution(1, ids, make([]byte, 32), expected, session, 0)
	require.Error(t, err)
	_, _, err = frost.NewKeygenStateWithContribution(1, party.IDSlice{1, 1, 2}, contributions[0][:], expected, session, 0)
	require.Error(t, err)

	for _, test := range []struct {
		name  string
		alter func(i int, contribution [32]byte) ([32]byte, []byte)
	}{
		{"matching", func(_ int, c [32]byte) ([32]byte, []byte) { return c, session }},
		{"different contribution", func(i int, c [32]byte) ([32]byte, []byte) {
			if i == 0 {
				c[0] = 9
			}
			return c, session
		}},
		{"different session", func(i int, c [32]byte) ([32]byte, []byte) {
			if i == 0 {
				return c, []byte("other session")
			}
			return c, session
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var states [3]*state.State
			var outputs [3]*keygen.Output
			for i, id := range ids {
				c, sid := test.alter(i, contributions[i])
				var err error
				states[i], outputs[i], err = frost.NewKeygenStateWithContribution(id, ids, c[:], expected, sid, 0)
				require.NoError(t, err)
			}
			var incoming [][]byte
			for step := 0; step < 3; step++ {
				var outgoing [][]byte
				for _, s := range states {
					messages, err := helpers.PartyRoutine(incoming, s)
					if err != nil {
						require.NotEqual(t, "matching", test.name)
						return
					}
					outgoing = append(outgoing, messages...)
				}
				incoming = outgoing
			}
			require.Equal(t, "matching", test.name)
			for i, output := range outputs {
				require.True(t, states[i].IsFinished())
				require.Equal(t, expected, output.Public.GroupKey.ToEd25519())
				require.Equal(t, party.Size(2), output.Public.Threshold)
			}
		})
	}
}

func TestKeygenQueuesFutureShareAfterCommitment(t *testing.T) {
	ids := party.IDSlice{1, 2, 3}
	var states [3]*state.State
	var commitments [3]*messages.Message
	for i, id := range ids {
		s, _, err := frost.NewKeygenState(id, ids, 2, 0)
		require.NoError(t, err)
		states[i] = s
		out := s.ProcessAll()
		require.Len(t, out, 1)
		commitments[i] = out[0]
	}
	// Serialize before any node advances, as the transport does.
	var wire [3][]byte
	for i, message := range commitments {
		data, err := message.MarshalBinary()
		require.NoError(t, err)
		wire[i] = data
	}
	deliver := func(to, from int) {
		var message messages.Message
		require.NoError(t, message.UnmarshalBinary(wire[from]))
		require.NoError(t, states[to].HandleMessage(&message))
	}
	deliver(0, 1)
	deliver(1, 0)
	deliver(1, 2)
	out := states[1].ProcessAll()
	require.Len(t, out, 2)
	for _, message := range out {
		if message.To == ids[0] {
			require.NoError(t, states[0].HandleMessage(message))
			require.Error(t, states[0].HandleMessage(message))
		}
	}
	deliver(0, 2)
	out = states[0].ProcessAll()
	require.NoError(t, states[0].Err())
	require.Len(t, out, 2)
}
