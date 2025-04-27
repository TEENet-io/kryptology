package frost

import (
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Round 1 of the secret resharing protocol
// https://conduition.io/cryptography/shamir-resharing/
//
// Inputs:
// 1. bcast   - contains the commitments broadcast by the old participants
//            	map(oldId => ResharingBcast)
// 2. p2psend - contains the shares computed by the old participants and
// 				sent to the new participants
//				map(oldId => share)
// Outputs:
// 1. Set SkShare = \sum_{j \in S} LagCoef_j^S g_j(i)
// 2. Set Commitments[k] = \sum_{j \in S} LagCoef_j^S A(j,k)
// 3. Set VerificationKey = Commitments[0]

// ResharingRound2 is called by a new participant who will hold a new key share
func (dp *DkgParticipant) ResharingRound2(
	oldThreshold int,
	bcast map[uint32]*ResharingBcast,
	p2psend map[uint32]*sharing.ShamirShare,
) error {
	if dp == nil || dp.Curve == nil {
		return internal.ErrNilArguments
	}

	curve := dp.Curve
	S := make([]uint32, 0, len(bcast))
	for id := range bcast {
		S = append(S, id)
	}

	Gj := make(map[uint32]curves.Scalar, len(S))
	var phi0 curves.Point
	for _, i := range S {
		gj, err := curve.Scalar.SetBytes(p2psend[i].Value)
		if err != nil {
			return err
		}

		Gj[i] = gj
		if phi0 == nil {
			phi0 = bcast[i].PHIs[0]
		}

		// Verify the validity of inputs
		// 		p2psend[i] = sum_{k=1}^{t-1} (bcast[i].PHIs[k] * i^k)
		// 						+ sum_{k=1}^{t'-1} (bcast[i].As[k] * dp.Id^k)
		A0, err := EvalCommitmentPoly(curve, bcast[i].PHIs, curve.Scalar.New(int(i)))
		if err != nil {
			return err
		}
		As := bcast[i].As
		As[0] = A0
		v, err := EvalCommitmentPoly(curve, As, curve.Scalar.New(int(dp.Id)))
		if err != nil {
			return err
		}
		if !v.Equal(curve.ScalarBaseMult(gj)) {
			return fmt.Errorf("invalid share g_%d(%d)", i, int(dp.Id))
		}
	}

	// Get the lagrange coefficients
	scheme, err := sharing.NewShamir(uint32(oldThreshold), uint32(len(S)), curve)
	if err != nil {
		return err
	}
	lCoeffs, err := scheme.LagrangeCoeffs(S)
	if err != nil {
		return err
	}

	// Compute the new secret share
	skShare := curve.Scalar.Zero()
	for _, i := range S {
		skShare = skShare.Add(lCoeffs[i].Mul(Gj[i]))
	}

	// Compute the new commiments
	commitments := append([]curves.Point{}, phi0)
	for k := 1; k < int(dp.Threshold); k++ {
		commitment := curve.Point.Identity()
		for _, i := range S {
			commitment = commitment.Add(bcast[i].As[k].Mul(lCoeffs[i]))
		}
		commitments = append(commitments, commitment)
	}

	v, err := EvalCommitmentPoly(curve, commitments, curve.Scalar.New(int(dp.Id)))
	if err != nil {
		return err
	}
	if !v.Equal(curve.ScalarBaseMult(skShare)) {
		panic("invalid share")
	}

	dp.Commitments = commitments
	dp.SkShare = skShare
	dp.VerificationKey = commitments[0]

	return nil
}
