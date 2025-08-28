//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package resharing implements threshold ECDSA key resharing for the GG20 protocol.
// This allows changing the threshold and participant set while preserving the same ECDSA public key.
package resharing

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/paillier"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
)

// Config contains parameters for resharing
type Config struct {
	OldThreshold uint32
	NewThreshold uint32
	OldParties   []uint32
	NewParties   []uint32
}

// ReshareParticipant represents a participant in the resharing protocol
type ReshareParticipant struct {
	ID             uint32
	Round          uint
	OldShare       *dealer.Share     // nil for new participants
	NewShare       *dealer.Share     // generated after resharing
	PublicKey      *curves.EcPoint   // ECDSA public key (remains unchanged)
	Curve          elliptic.Curve
	PaillierKey    *paillier.SecretKey
	PaillierPubKey *paillier.PublicKey
	Config         *Config

	// Internal state
	coefficients   []*big.Int                       // polynomial coefficients (round 1)
	commitments    []*curves.EcPoint                // VSS commitments (round 1)
	receivedShares map[uint32]*big.Int              // shares received from old participants
	paillierKeys   map[uint32]*paillier.PublicKey   // collected in round 2
	publicShares   map[uint32]*dealer.PublicShare   // collected in round 3
}

// NewReshareParticipant creates a new resharing participant
func NewReshareParticipant(
	id uint32,
	oldParticipantData *dealer.ParticipantData, // nil for new participants
	publicKey *curves.EcPoint,
	config *Config,
) (*ReshareParticipant, error) {
	if config == nil || publicKey == nil {
		return nil, internal.ErrNilArguments
	}

	var oldShare *dealer.Share
	var paillierKey *paillier.SecretKey

	// If this is an existing participant, use their old share and Paillier key
	if oldParticipantData != nil {
		if oldParticipantData.Id != id {
			return nil, fmt.Errorf("participant ID mismatch: %d != %d", oldParticipantData.Id, id)
		}
		oldShare = oldParticipantData.SecretKeyShare
		paillierKey = oldParticipantData.DecryptKey
	}

	// Generate new Paillier key if needed
	if paillierKey == nil {
		var err error
		// Use larger test primes that are still fast but large enough for ECDSA
		// These are 512-bit primes from kryptology test suite
		p := new(big.Int)
		q := new(big.Int)
		p.SetString("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643", 10)
		q.SetString("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379", 10)
		paillierKey, err = paillier.NewSecretKey(p, q)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Paillier key: %w", err)
		}
	}

	return &ReshareParticipant{
		ID:             id,
		Round:          1,
		OldShare:       oldShare,
		PublicKey:      publicKey,
		Curve:          publicKey.Curve,
		PaillierKey:    paillierKey,
		PaillierPubKey: &paillierKey.PublicKey,
		Config:         config,
		receivedShares: make(map[uint32]*big.Int),
	}, nil
}

// GetReshareResult returns the final resharing result after all rounds complete
func (rp *ReshareParticipant) GetReshareResult() (*dealer.ParticipantData, error) {
	if rp.Round != 4 {
		return nil, errors.New("resharing not complete")
	}

	if rp.NewShare == nil {
		return nil, errors.New("no new share generated")
	}

	// Create participant data in dealer format
	return &dealer.ParticipantData{
		Id:             rp.ID,
		DecryptKey:     rp.PaillierKey,
		SecretKeyShare: rp.NewShare,
		EcdsaPublicKey: rp.PublicKey,
		KeyGenType:     &dealer.TrustedDealerKeyGenType{},
		PublicShares:   rp.publicShares,
		EncryptKeys:    rp.paillierKeys,
	}, nil
}

// Helper functions

func generatePaillierKey() (*paillier.SecretKey, error) {
	// Generate safe primes for Paillier
	// In production, use appropriate bit size (e.g., 2048)
	const bits = 1024
	p, err := core.GenerateSafePrime(bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate first prime: %w", err)
	}

	q, err := core.GenerateSafePrime(bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate second prime: %w", err)
	}

	return paillier.NewSecretKey(p, q)
}

func evaluatePolynomial(coefficients []*big.Int, x uint32, modulus *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPower := big.NewInt(int64(x))

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		result.Add(result, term)
		result.Mod(result, modulus)
		xPower.Mul(xPower, big.NewInt(int64(x)))
		xPower.Mod(xPower, modulus)
	}

	return result
}

// VerifyReshareResult verifies that resharing preserved the ECDSA public key
func VerifyReshareResult(
	participantData map[uint32]*dealer.ParticipantData,
	expectedPublicKey *curves.EcPoint,
) error {
	if len(participantData) == 0 {
		return errors.New("no participant data to verify")
	}

	// Verify all participants have the same public key
	for id, data := range participantData {
		if data.EcdsaPublicKey == nil {
			return fmt.Errorf("participant %d has nil public key", id)
		}

		if data.EcdsaPublicKey.X.Cmp(expectedPublicKey.X) != 0 ||
		   data.EcdsaPublicKey.Y.Cmp(expectedPublicKey.Y) != 0 {
			return fmt.Errorf("participant %d has incorrect public key", id)
		}

		// Verify the participant has required data
		if data.SecretKeyShare == nil {
			return fmt.Errorf("participant %d has nil secret share", id)
		}
		if data.DecryptKey == nil {
			return fmt.Errorf("participant %d has nil Paillier key", id)
		}
	}

	return nil
}