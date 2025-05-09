package frost

import (
	crand "crypto/rand"
	"fmt"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/sharing"
)

// Round 1 of the secret resharing protocol
// https://conduition.io/cryptography/shamir-resharing/
//
// Inputs:
// 1. Participant that holds a valid secret share before resharing
// 2. New threshold t'
// 3. Ids of new participants who will hold new secret shares after resharing
// Ouputs to be broadcast:
// 1. Commitments of coefficients of the newly sampled polynomial with degree (t' - 1)
// 	  { A(i,k) = a(i,k) * G }_{k=1..t'-1}
// 2. Commitments of coefficients of the original global polynomial
// 	  { PHI(i,k) }_{k=0..t-1}
// Outputs to be sent to each participant:
// 1. { g_j = z(i) + \sum_{k=1..t'-1} a(i,k) * j^k }
//    where {j \in S} are ids of the new participants who will hold a new secret share

type ResharingBcast struct {
	As   []curves.Point
	PHIs []curves.Point
}

type ResharingP2PSend = map[uint32]*sharing.ShamirShare

// ResharingRound1 is called by a participant who hold a valid secret share
// before resharing to generate inputs for resharing round 2.
//
// @param rp - participant who participates in the resharing protocol
// @return bcast - contains commitments of the randomly sampled polynomial coefficients, As,
// and the commitments of the original global polynomial coefficients, PHIs
// @return p2psend - contains shares to be sent to the new participants privately
func (r *Resharing) ResharingRound1(rp *DkgParticipant) (*ResharingBcast, ResharingP2PSend, error) {
	// Make sure the participant and its required fields are not empty
	if r == nil || r.curve == nil || rp == nil || rp.SkShare == nil || rp.Commitments == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Check if rp.Id is in r.ResharingParticipantIDs
	found := false
	for _, id := range r.ResharingParticipantIDs {
		if id == rp.Id {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("participant %d is not in the resharing participant IDs", rp.Id)
	}

	if r.curve.Name != rp.Curve.Name {
		return nil, nil, fmt.Errorf("curve mismatch: %s != %s", r.curve.Name, rp.Curve.Name)
	}

	verifier, shares, err := r.feldman.Split(rp.SkShare, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	bcast := &ResharingBcast{
		As:   verifier.Commitments,
		PHIs: rp.Commitments,
	}

	// Compute shares for new participants
	p2psend := make(ResharingP2PSend, len(r.NewParticipantIDs))
	for id, value := range shares {
		p2psend[id] = value
	}

	return bcast, p2psend, nil
}
