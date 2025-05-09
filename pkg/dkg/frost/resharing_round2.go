package frost

import (
	"fmt"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/sharing"
)

// Round 2 of the secret resharing protocol
// https://conduition.io/cryptography/shamir-resharing/
//
// Inputs:
// 1. bcast   - contains commitments of the randomly sampled polynomial coefficients
// 			    broadcast by participants holding the old key shares
//            	map(oldId => ResharingBcast)
// 2. p2psend - contains the shares computed by participants holding the hold key and
// 				sent to the new participants
//				map(oldId => share)
// Outputs:
// 1. Set SkShare = \sum_{i \in S} LarangeCoef_i^S * g_j(i)
//    where j is the identity of the new participant
// 2. Set Commitments[k] = \sum_{i \in S} LagrangeCoef_i^S * A(i,k)
// 	  where A(i,k) is the commitment of coefficient a(i,k) randomly sampled by i
// 3. Set VerificationKey = Commitments[0]

// ResharingRound2 is called by a new participant who will hold a new key share
// to generate its new secret share and commitments.
//
// @param dp - new participant who will hold a new secret share
// @param oldThreshold - orginal threshold t
// @param bcast - contains broadcast data from all participants holding old secret shares
// @param p2psend - contains all shares sent to the current new participant
// @return error - nil if successful, otherwise an error
func (r *Resharing) ResharingRound2(
	np *DkgParticipant,
	bcast map[uint32]*ResharingBcast,
	p2psend map[uint32]*sharing.ShamirShare,
) error {
	if r == nil || r.curve == nil || bcast == nil || p2psend == nil || np == nil {
		return internal.ErrNilArguments
	}

	if r.curve.Name != np.Curve.Name {
		return fmt.Errorf("curve mismatch: %s != %s", r.curve.Name, np.Curve.Name)
	}

	// Check if np.Id is in r.NewParticipantIDs
	found := false
	for _, id := range r.NewParticipantIDs {
		if id == np.Id {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("participant %d is not in the new participant IDs", np.Id)
	}

	if len(bcast) != len(r.ResharingParticipantIDs) {
		return fmt.Errorf("invalid broadcast data length")
	}

	if len(p2psend) != len(r.ResharingParticipantIDs) {
		return fmt.Errorf("invalid p2p data length")
	}

	for _, data := range bcast {
		if data == nil || data.As == nil || data.PHIs == nil ||
			len(data.As) != int(r.Threshold) || len(data.PHIs) > len(bcast) {
			return fmt.Errorf("invalid broadcast data")
		}
	}

	for _, data := range p2psend {
		if data == nil {
			return fmt.Errorf("invalid p2p data")
		}
	}

	curve := r.curve
	S := r.ResharingParticipantIDs
	j := np.Id

	// Shares computed by participants in S
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

		A0, err := EvalCommitmentPoly(curve, bcast[i].PHIs, curve.Scalar.New(int(i)))
		if err != nil {
			return err
		}
		As := bcast[i].As
		As[0] = A0
		v, err := EvalCommitmentPoly(curve, As, curve.Scalar.New(int(j)))
		if err != nil {
			return err
		}
		if !v.Equal(curve.ScalarBaseMult(gj)) {
			return fmt.Errorf("invalid share g_%d[%d]", i, int(j))
		}
	}

	// Get the lagrange coefficients
	scheme, err := sharing.NewShamir(uint32(len(S)), uint32(len(S)), curve)
	if err != nil {
		return err
	}
	lCoeffs, err := scheme.LagrangeCoeffs(S)
	if err != nil {
		return err
	}

	// Compute the new secret share
	// 		z'_j = \sum_{i \in S} LagrangeCoef_i^S * g_j(i)
	skShare := curve.Scalar.Zero()
	for _, i := range S {
		skShare = skShare.Add(lCoeffs[i].Mul(Gj[i]))
	}

	// Compute the new commiments
	// 		Commitments[k] = \sum_{i \in S} LagrangeCoef_i^S * A(i,k)
	commitments := append([]curves.Point{}, phi0)
	for k := 1; k < int(r.Threshold); k++ {
		commitment := curve.Point.Identity()
		for _, i := range S {
			commitment = commitment.Add(bcast[i].As[k].Mul(lCoeffs[i]))
		}
		commitments = append(commitments, commitment)
	}

	v, err := EvalCommitmentPoly(curve, commitments, curve.Scalar.New(int(j)))
	if err != nil {
		return err
	}
	if !v.Equal(curve.ScalarBaseMult(skShare)) {
		panic("invalid share")
	}

	np.Commitments = commitments
	np.SkShare = skShare.Clone()
	np.VerificationKey = commitments[0]
	np.VkShare = curve.ScalarBaseMult(skShare)

	return nil
}
