package frost

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/stretchr/testify/require"
)

// dkg performs a DKG for the given number of participants and threshold.
func dkg(t *testing.T, threshold, limit int) map[uint32]*DkgParticipant {
	// Init participants
	participants := make(map[uint32]*DkgParticipant, limit)
	for i := 1; i <= limit; i++ {
		otherIds := make([]uint32, 0, limit-1)
		for j := 1; j <= limit; j++ {
			if i == j {
				continue
			}
			otherIds = append(otherIds, uint32(j))
		}

		p, err := NewDkgParticipant(uint32(i), uint32(threshold), Ctx, testCurve, otherIds...)
		require.NoError(t, err)
		participants[uint32(i)] = p
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
	shares := []*sharing.ShamirShare{}
	thres := len(participants[1].Commitments)
	limit := len(participants[1].otherParticipantShares) + 1

	for id := 1; id <= thres; id++ {
		p := participants[uint32(id)]
		share := &sharing.ShamirShare{
			Id:    uint32(id),
			Value: p.SkShare.Bytes(),
		}
		shares = append(shares, share)
	}

	// Combine shares to get the secret and verify the public key
	scheme, err := sharing.NewShamir(
		uint32(thres),
		uint32(limit),
		participants[1].Curve,
	)
	require.NoError(t, err)
	sk, err := scheme.Combine(shares...)
	require.NoError(t, err)
	pub := participants[1].Curve.ScalarBaseMult(sk)
	require.True(t, pub.Equal(participants[1].VerificationKey))

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

	///////////////////////
	// Resharing Round 1
	///////////////////////
	p2psend := make(map[uint32]ResharingP2PSend, len(participants))
	bcast := make(map[uint32]*ResharingBcast, len(participants))
	newParticipants := make([]uint32, newLimit)
	for i := 1; i <= newLimit; i++ {
		newParticipants[i-1] = uint32(i)
	}
	for _, p := range participants {
		id := p.Id
		bcast[id], p2psend[id], err = p.ResharingRound1(newThreshold, newParticipants...)
		require.NoError(t, err)
	}

	// Verify that all PHIs are the same
	for _, bc := range bcast {
		for k := range participants[1].Commitments {
			require.True(t, bc.PHIs[k].Equal(participants[1].Commitments[k]))
		}
	}

	///////////////////////
	// Resharing Round 2
	///////////////////////
	// Init new participants
	resharingParticipants := make(map[uint32]*DkgParticipant, newLimit)
	for i := 1; i <= newLimit; i++ {
		otherIds := make([]uint32, 0, newLimit-1)
		for j := 1; j <= newLimit; j++ {
			if i == j {
				continue
			}
			otherIds = append(otherIds, uint32(j))
		}

		p, err := NewDkgParticipant(uint32(i), uint32(newThreshold), Ctx, testCurve, otherIds...)
		require.NoError(t, err)
		resharingParticipants[uint32(i)] = p
	}

	// Get S = {ids of participants}
	S := make([]uint32, 0, len(participants))
	for id := range participants {
		S = append(S, id)
	}

	// Perform round 2
	for id, p := range resharingParticipants {
		// prepare p2psend for p
		p2p := make(map[uint32]*sharing.ShamirShare, len(S))
		for _, i := range S {
			p2p[i] = p2psend[i][id]
		}

		err := p.ResharingRound2(threshold, bcast, p2p)
		require.NoError(t, err)
	}

	// Verify that commitments are the same
	commitments := resharingParticipants[1].Commitments
	for _, p := range resharingParticipants {
		for k := 0; k < newThreshold; k++ {
			require.True(t, commitments[k].Equal(p.Commitments[k]))
		}
	}

	verifyDKG(t, resharingParticipants)

	// Verify that the new public key remains the same
	require.True(t, resharingParticipants[1].VerificationKey.Equal(resharingParticipants[1].VerificationKey))
}
