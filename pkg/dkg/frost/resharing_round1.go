package frost

import (
	crand "crypto/rand"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Round 1 of the secret resharing protocol
// https://conduition.io/cryptography/shamir-resharing/
//
// Inputs:
// 1. Participant that holds a valid secret share before resharing
// 2. New threshold t'
// 3. New set of participants
// Ouputs to be broadcast:
// 1. Commitments of coefficients of the newly sampled polynomial with degree (t' - 1)
// 	  { A(i,k) = a(i,k) * G }_k=1..t'-1
// 2. Commitments of coefficients of the original global polynomial
// 	  { PHI(i,k) }_k=0..t-1
// Outputs to be sent to each participant:
// 1. g_i(j) = z(i) + \sum_k={1..t'-1} a(i,k) * j^k

type ResharingBcast struct {
	As   []curves.Point
	PHIs []curves.Point
}

type ResharingP2PSend = map[uint32]*sharing.ShamirShare

// ResharingRound1 is called by each participants who hold the old key shares
func (dp *DkgParticipant) ResharingRound1(
	newThreshold int, newParticipants ...uint32,
) (*ResharingBcast, ResharingP2PSend, error) {
	// Make sure the participant and its required fields are not empty
	if dp == nil || dp.Curve == nil || dp.SkShare == nil || dp.Commitments == nil {
		return nil, nil, internal.ErrNilArguments
	}

	curve := dp.Curve

	// Randomly sample coefficients { a(i,k) }_{k=1}^{t'-1} of a polynomial with degree (threshold - 1)
	// with its constant set to dp.SkShare (z_i)
	poly := &sharing.Polynomial{
		Coefficients: make([]curves.Scalar, newThreshold),
	}
	poly.Coefficients[0] = dp.SkShare.Clone()
	for k := 1; k < newThreshold; k++ {
		poly.Coefficients[k] = curve.Scalar.Random(crand.Reader)
	}

	// Compute commitments for the coefficients
	As := make([]curves.Point, newThreshold)
	As[0] = curve.ScalarBaseMult(dp.SkShare)
	for k := 1; k < newThreshold; k++ {
		As[k] = curve.ScalarBaseMult(poly.Coefficients[k])
	}
	bcast := &ResharingBcast{
		As:   As,
		PHIs: dp.Commitments,
	}

	// Compute shares for new participants
	p2psend := make(ResharingP2PSend, len(newParticipants))
	for _, j := range newParticipants {
		share := poly.Evaluate(curve.Scalar.New(int(j)))

		p2psend[j] = &sharing.ShamirShare{
			Id:    j,
			Value: share.Bytes(),
		}

		v, _ := EvalCommitmentPoly(curve, As, curve.Scalar.New(int(j)))
		if !v.Equal(curve.ScalarBaseMult(share)) {
			panic("invalid share")
		}
	}

	return bcast, p2psend, nil
}
