//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package resharing

import (
	"fmt"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/paillier"
)

// ReshareRound2Bcast contains Paillier public key to be broadcast
type ReshareRound2Bcast struct {
	ParticipantID uint32
	PublicKey     *paillier.PublicKey
}

// ReshareRound2 distributes Paillier public keys
func (rp *ReshareParticipant) ReshareRound2() (*ReshareRound2Bcast, error) {
	if rp == nil || rp.PaillierPubKey == nil {
		return nil, internal.ErrNilArguments
	}

	if rp.Round != 2 {
		return nil, internal.ErrInvalidRound
	}

	// Don't advance round here, let Accept do it
	return &ReshareRound2Bcast{
		ParticipantID: rp.ID,
		PublicKey:     rp.PaillierPubKey,
	}, nil
}

// ReshareRound2Accept collects Paillier keys from all participants
func (rp *ReshareParticipant) ReshareRound2Accept(messages []*ReshareRound2Bcast) error {
	if rp == nil || rp.Config == nil {
		return internal.ErrNilArguments
	}

	if rp.Round != 2 {
		return internal.ErrInvalidRound
	}

	// Store Paillier keys
	rp.paillierKeys = make(map[uint32]*paillier.PublicKey)
	for _, msg := range messages {
		if msg.PublicKey == nil {
			return fmt.Errorf("nil Paillier key from participant %d", msg.ParticipantID)
		}
		rp.paillierKeys[msg.ParticipantID] = msg.PublicKey
	}

	// Verify we have keys from all new participants
	for _, id := range rp.Config.NewParties {
		if _, ok := rp.paillierKeys[id]; !ok && id != rp.ID {
			return fmt.Errorf("missing Paillier key from participant %d", id)
		}
	}

	// Add our own key
	rp.paillierKeys[rp.ID] = rp.PaillierPubKey

	// Advance to next round
	rp.Round = 3
	return nil
}
