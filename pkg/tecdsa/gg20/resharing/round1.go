//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package resharing

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	v1 "github.com/TEENet-io/kryptology/pkg/sharing/v1"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
)

// ReshareRound1Bcast contains values to be broadcast to all new participants after round 1
type ReshareRound1Bcast struct {
	FromID      uint32            // Sender ID (old participant)
	ToID        uint32            // Recipient ID (new participant)
	Share       *big.Int          // The secret share for the recipient
	Commitments []*curves.EcPoint // Feldman VSS commitments
}

// ReshareRound1 generates shares for new participants (old participants only)
// This implements Feldman VSS for secure resharing
func (rp *ReshareParticipant) ReshareRound1() (map[uint32]*ReshareRound1Bcast, error) {
	if rp == nil || rp.Config == nil {
		return nil, internal.ErrNilArguments
	}

	// Only old participants who have shares can execute this round
	if rp.OldShare == nil {
		return nil, errors.New("only old participants with shares can execute round 1")
	}

	if rp.Round != 1 {
		return nil, internal.ErrInvalidRound
	}

	// Get the secret share from the old participant
	secret := rp.OldShare.ShamirShare.Value.BigInt()
	threshold := int(rp.Config.NewThreshold)
	
	// Calculate Lagrange coefficient for this participant at x=0
	// This is needed when all old participants contribute to preserve the secret
	lagrangeCoeff := calculateLagrangeCoefficient(rp.ID, rp.Config.OldParties, rp.Curve.Params().N)
	
	// Apply Lagrange coefficient to the share
	// This ensures proper reconstruction when all old participants contribute
	adjustedSecret := new(big.Int).Mul(secret, lagrangeCoeff)
	adjustedSecret.Mod(adjustedSecret, rp.Curve.Params().N)

	// Create polynomial coefficients for Feldman VSS
	// IMPORTANT: For proper resharing that preserves the public key,
	// we use the Lagrange-adjusted share as the constant term and generate
	// random coefficients for the higher degree terms.
	// This ensures that when all old participants do this and new participants
	// combine the shares, the original secret is preserved.
	rp.coefficients = make([]*big.Int, threshold)
	rp.coefficients[0] = adjustedSecret // Use the Lagrange-adjusted share as a_0

	// Generate random coefficients for degree 1 to threshold-1
	for i := 1; i < threshold; i++ {
		coef, err := rand.Int(rand.Reader, rp.Curve.Params().N)
		if err != nil {
			return nil, fmt.Errorf("failed to generate coefficient: %w", err)
		}
		rp.coefficients[i] = coef
	}

	// Generate commitments C_i = g^{a_i} for Feldman VSS
	rp.commitments = make([]*curves.EcPoint, threshold)
	for i := 0; i < threshold; i++ {
		commitment, err := curves.NewScalarBaseMult(rp.Curve, rp.coefficients[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate commitment: %w", err)
		}
		rp.commitments[i] = commitment
	}

	// Generate shares for each new participant
	messages := make(map[uint32]*ReshareRound1Bcast)
	for _, newID := range rp.Config.NewParties {
		// Evaluate polynomial at newID: f(newID) = sum(a_i * newID^i)
		share := evaluatePolynomial(rp.coefficients, newID, rp.Curve.Params().N)

		messages[newID] = &ReshareRound1Bcast{
			FromID:      rp.ID,
			ToID:        newID,
			Share:       share,
			Commitments: rp.commitments,
		}
	}

	// Old participants don't set their NewShare here - they'll get it from combining
	// shares they receive from other old participants in Round1Accept

	// Advance to next round
	rp.Round = 2
	return messages, nil
}

// ReshareRound1Accept processes received shares (new participants only)
func (rp *ReshareParticipant) ReshareRound1Accept(messages []*ReshareRound1Bcast) error {
	if rp == nil || rp.Config == nil {
		return internal.ErrNilArguments
	}

	// Old participants who are also new participants need to process shares too
	// They're already in round 2 after generating shares
	if rp.OldShare != nil && rp.Round == 2 {
		// Old participant receiving shares from other old participants
		// Don't check round since they've already advanced
	} else if rp.Round != 1 {
		// New participants must be in round 1
		return internal.ErrInvalidRound
	}

	// IMPORTANT: For proper resharing that preserves the public key,
	// we need ALL old participants to send shares, not just threshold
	expectedOldParticipants := len(rp.Config.OldParties)
	if len(messages) != expectedOldParticipants {
		return fmt.Errorf("need shares from ALL old participants for proper resharing: got %d, need %d",
			len(messages), expectedOldParticipants)
	}

	// Verify and store each share
	for _, msg := range messages {
		if msg.ToID != rp.ID {
			return fmt.Errorf("received share for wrong participant: expected %d, got %d",
				rp.ID, msg.ToID)
		}

		// Verify share using Feldman VSS
		if !rp.verifyFeldmanShare(msg) {
			return fmt.Errorf("invalid share from participant %d", msg.FromID)
		}

		// Store valid share
		rp.receivedShares[msg.FromID] = msg.Share
	}

	// Combine shares from ALL old participants
	// When ALL old participants contribute (which is required for preserving the public key),
	// we simply sum their sub-shares. Each old participant created a polynomial with their
	// share as the constant term and evaluated it at the new participant's ID.
	// The sum of all these evaluations gives the new participant's share.
	newShareValue := new(big.Int)
	
	// Simply sum all received shares
	for _, share := range rp.receivedShares {
		newShareValue.Add(newShareValue, share)
		newShareValue.Mod(newShareValue, rp.Curve.Params().N)
	}

	// Create the new share structure
	field := curves.NewField(rp.Curve.Params().N)
	rp.NewShare = &dealer.Share{
		ShamirShare: &v1.ShamirShare{
			Identifier: rp.ID,
			Value:      field.NewElement(newShareValue),
		},
	}

	// Generate public share point for verification
	publicSharePoint, err := curves.NewScalarBaseMult(rp.Curve, newShareValue)
	if err != nil {
		return fmt.Errorf("failed to generate public share: %w", err)
	}
	rp.NewShare.Point = publicSharePoint

	// Advance to next round (unless already in round 2 for old participants)
	if rp.Round == 1 {
		rp.Round = 2
	}
	return nil
}

// verifyFeldmanShare verifies a share using Feldman VSS commitments
func (rp *ReshareParticipant) verifyFeldmanShare(msg *ReshareRound1Bcast) bool {
	// Verify: g^share = product(commitment_i^(id^i))
	// This ensures the share is consistent with the polynomial commitments

	// Compute expected value from commitments
	var expected *curves.EcPoint
	xPower := big.NewInt(1)
	idBig := big.NewInt(int64(rp.ID))

	for i, commitment := range msg.Commitments {
		if i == 0 {
			expected = commitment
		} else {
			xPower.Mul(xPower, idBig)
			xPower.Mod(xPower, rp.Curve.Params().N)

			term, err := commitment.ScalarMult(xPower)
			if err != nil {
				return false
			}

			expected, err = expected.Add(term)
			if err != nil {
				return false
			}
		}
	}

	// Compute actual value from share
	actual, err := curves.NewScalarBaseMult(rp.Curve, msg.Share)
	if err != nil {
		return false
	}

	// Compare expected and actual
	return actual.X.Cmp(expected.X) == 0 && actual.Y.Cmp(expected.Y) == 0
}

// calculateLagrangeCoefficient calculates the Lagrange coefficient for a given party at x=0
func calculateLagrangeCoefficient(partyID uint32, allPartyIDs []uint32, modulus *big.Int) *big.Int {
	// L_i(0) = product((0 - x_j) / (x_i - x_j)) for all j != i
	// Since we evaluate at 0: L_i(0) = product((-x_j) / (x_i - x_j))
	
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	
	for _, otherID := range allPartyIDs {
		if otherID == partyID {
			continue
		}
		
		// Numerator: multiply by -otherID
		term := big.NewInt(-int64(otherID))
		numerator.Mul(numerator, term)
		numerator.Mod(numerator, modulus)
		
		// Denominator: multiply by (partyID - otherID)
		diff := big.NewInt(int64(partyID) - int64(otherID))
		denominator.Mul(denominator, diff)
		denominator.Mod(denominator, modulus)
	}
	
	// Ensure positive values in modular arithmetic
	if numerator.Sign() < 0 {
		numerator.Add(numerator, modulus)
	}
	if denominator.Sign() < 0 {
		denominator.Add(denominator, modulus)
	}
	
	// Calculate numerator * denominator^(-1) mod modulus
	denomInv := new(big.Int).ModInverse(denominator, modulus)
	if denomInv == nil {
		// This shouldn't happen with proper party IDs
		panic("failed to compute modular inverse in Lagrange coefficient")
	}
	
	result := new(big.Int).Mul(numerator, denomInv)
	result.Mod(result, modulus)
	
	return result
}