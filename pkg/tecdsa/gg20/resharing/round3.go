//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package resharing

import (
	"fmt"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
)

// ReshareRound3Bcast contains public share information
type ReshareRound3Bcast struct {
	ParticipantID uint32
	PublicShare   *dealer.PublicShare
}

// ReshareRound3 shares public share points
func (rp *ReshareParticipant) ReshareRound3() (*ReshareRound3Bcast, error) {
	if rp == nil || rp.NewShare == nil {
		return nil, internal.ErrNilArguments
	}

	if rp.Round != 3 {
		return nil, internal.ErrInvalidRound
	}

	if rp.NewShare.Point == nil {
		return nil, fmt.Errorf("public share point not computed")
	}

	// Don't advance round here, let Accept do it
	return &ReshareRound3Bcast{
		ParticipantID: rp.ID,
		PublicShare:   &dealer.PublicShare{Point: rp.NewShare.Point},
	}, nil
}

// ReshareRound3Accept collects public shares from all participants
func (rp *ReshareParticipant) ReshareRound3Accept(messages []*ReshareRound3Bcast) error {
	if rp == nil || rp.Config == nil {
		return internal.ErrNilArguments
	}

	if rp.Round != 3 {
		return internal.ErrInvalidRound
	}

	// Store public shares
	rp.publicShares = make(map[uint32]*dealer.PublicShare)
	for _, msg := range messages {
		if msg.PublicShare == nil || msg.PublicShare.Point == nil {
			return fmt.Errorf("nil public share from participant %d", msg.ParticipantID)
		}
		rp.publicShares[msg.ParticipantID] = msg.PublicShare
	}

	// Add our own public share
	rp.publicShares[rp.ID] = &dealer.PublicShare{Point: rp.NewShare.Point}

	// Verify we have public shares from all new participants
	if len(rp.publicShares) != len(rp.Config.NewParties) {
		return fmt.Errorf("missing public shares: got %d, expected %d",
			len(rp.publicShares), len(rp.Config.NewParties))
	}

	// Advance to completion
	rp.Round = 4
	return nil
}