package frost

import (
	"testing"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/sharing"
	"github.com/stretchr/testify/require"
)

// dkg performs a DKG for the given number of participants and threshold.
func dkg(t *testing.T, threshold, limit int) map[uint32]*DkgParticipant {
	// Init participants
	participants := make(map[uint32]*DkgParticipant, limit)

	IDs, _ := internal.SampleUniqueUint32s(limit, 100, 2000)

	for i := 0; i < limit; i++ {
		idi := IDs[i]
		otherIds := make([]uint32, 0, limit-1)
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			otherIds = append(otherIds, IDs[j])
		}

		p, err := NewDkgParticipant(idi, uint32(threshold), Ctx, testCurve, otherIds...)
		require.NoError(t, err)
		participants[idi] = p
	}

	// DkG Round 1
	rnd1Bcast := make(map[uint32]*Round1Bcast, len(participants))
	rnd1P2p := make(map[uint32]Round1P2PSend, len(participants))
	for _, p := range participants {
		id := p.Id
		bcast, p2psend, err := p.Round1(nil)
		require.NoError(t, err)

		rnd1Bcast[id] = bcast
		rnd1P2p[id] = p2psend
	}

	// DkG Round 2
	for _, p := range participants {
		id := p.Id
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range p.otherParticipantShares {
			rnd1P2pForP[jid] = rnd1P2p[jid][id]
		}
		_, err := p.Round2(rnd1Bcast, rnd1P2pForP)
		require.NoError(t, err)
	}

	return participants
}

func verifyDKG(t *testing.T, participants map[uint32]*DkgParticipant) {
	id0 := uint32(0)
	for id := range participants {
		id0 = id
		break
	}
	p0 := participants[id0]

	shares := []*sharing.ShamirShare{}
	thres := p0.Threshold
	limit := p0.Limit()
	curve := p0.Curve

	for id, p := range participants {
		share := &sharing.ShamirShare{
			Id:    uint32(id),
			Value: p.SkShare.Bytes(),
		}
		shares = append(shares, share)
	}

	// Combine shares to get the secret and verify the public key
	scheme, err := sharing.NewShamir(thres, limit, curve)
	require.NoError(t, err)
	sk, err := scheme.Combine(shares...)
	require.NoError(t, err)
	pub := curve.ScalarBaseMult(sk)
	require.True(t, pub.Equal(p0.VerificationKey))

	// Check that all participants have the same public key
	for _, p := range participants {
		require.True(t, pub.Equal(p.VerificationKey))
		require.True(t, pub.Equal(p.Commitments[0]))
	}

	// Check shares
	for _, p := range participants {
		commitment, err := EvalCommitmentPoly(p.Curve, p.Commitments, p.Curve.Scalar.New(int(p.Id)))
		require.NoError(t, err)
		require.True(t, commitment.Equal(p.Curve.ScalarBaseMult(p.SkShare)))
	}
}

func TestDKG(t *testing.T) {
	participants := dkg(t, 3, 5)

	// Verify DKG
	verifyDKG(t, participants)
}

func TestNilArgs(t *testing.T) {
	_, err := NewResharing(3, nil, []uint32{1, 2, 3}, []uint32{4, 5, 6})
	require.Equal(t, err, internal.ErrNilArguments)
	_, err = NewResharing(3, testCurve, []uint32{}, []uint32{4, 5, 6})
	require.Equal(t, err, internal.ErrNilArguments)
	_, err = NewResharing(3, testCurve, []uint32{1, 2, 3}, []uint32{})
	require.Equal(t, err, internal.ErrNilArguments)
}

func TestDuplicateIDs(t *testing.T) {
	_, err := NewResharing(3, testCurve, []uint32{1, 2, 3, 2}, []uint32{1, 5, 6})
	require.Error(t, err)
	_, err = NewResharing(3, testCurve, []uint32{1, 2, 3}, []uint32{1, 2, 3, 3})
	require.Error(t, err)
}

func TestResharing(t *testing.T) {
	var (
		threshold = 3
		limit     = 5

		newThreshold = 4
		newLimit     = 7

		err error
	)

	// DKG
	participants := dkg(t, threshold, limit)
	verifyDKG(t, participants)

	var id0 uint32
	for id := range participants {
		id0 = id
		break
	}
	Ids := participants[id0].Ids()

	resharingParticipantIDs := Ids[:newThreshold]
	newParticipantIDs, _ := internal.SampleUniqueUint32s(newLimit, 100, 10000)

	r, err := NewResharing(uint32(newThreshold), testCurve, resharingParticipantIDs, newParticipantIDs)
	require.NoError(t, err)

	///////////////////////
	// Resharing Round 1
	///////////////////////
	p2pRnd1Out := make(map[uint32]ResharingP2PSend, len(resharingParticipantIDs))
	bcastRnd1Out := make(map[uint32]*ResharingBcast, len(resharingParticipantIDs))

	// Perform round 1
	for _, id := range resharingParticipantIDs {
		p := participants[id]
		id := p.Id
		bcastRnd1Out[id], p2pRnd1Out[id], err = r.ResharingRound1(p)
		require.NoError(t, err)
	}

	// Verify that all PHIs are the same
	refId := resharingParticipantIDs[0]
	for _, bc := range bcastRnd1Out {
		for k, commit := range participants[refId].Commitments {
			require.True(t, bc.PHIs[k].Equal(commit))
		}
	}

	///////////////////////
	// Resharing Round 2
	///////////////////////
	// Init new participants
	newParticipants := make(map[uint32]*DkgParticipant, newLimit)
	for _, i := range newParticipantIDs {
		otherIds := []uint32{}
		for _, j := range newParticipantIDs {
			if i == j {
				continue
			}
			otherIds = append(otherIds, j)
		}

		p, err := NewDkgParticipant(i, uint32(newThreshold), Ctx, testCurve, otherIds...)
		require.NoError(t, err)
		newParticipants[i] = p
	}

	// Perform round 2
	for id, p := range newParticipants {
		// prepare inputs for resharing round 2
		p2pRnd2In := make(map[uint32]*sharing.ShamirShare, len(resharingParticipantIDs))
		for _, i := range resharingParticipantIDs {
			p2pRnd2In[i] = p2pRnd1Out[i][id]
		}

		err := r.ResharingRound2(p, bcastRnd1Out, p2pRnd2In)
		require.NoError(t, err)
	}

	// Verify that commitments are the same
	commitments := newParticipants[r.NewParticipantIDs[0]].Commitments
	for _, p := range newParticipants {
		for k, c := range commitments {
			require.True(t, p.Commitments[k].Equal(c))
		}
	}

	verifyDKG(t, newParticipants)

	// Verify that the new public key remains the same
	p1 := newParticipants[r.NewParticipantIDs[0]]
	p2 := participants[resharingParticipantIDs[0]]
	require.True(t, p1.VerificationKey.Equal(p2.VerificationKey))
}
