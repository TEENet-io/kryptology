package frost

import (
	"fmt"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/sharing"
)

// Resharing is a structure that contains the parameters for resharing.
type Resharing struct {
	Threshold               uint32   // threshold for the reshared secret
	NewParticipantIDs       []uint32 // IDs of the participants holding the new secret shares
	ResharingParticipantIDs []uint32 // IDs of the participants holding the secret shares to be reshared

	curve   *curves.Curve
	feldman *sharing.Feldman
}

func NewResharing(
	threshold uint32, curve *curves.Curve,
	resharingParticipantIDs, newParticipantIDs []uint32,
) (*Resharing, error) {
	if curve == nil || len(newParticipantIDs) == 0 || len(resharingParticipantIDs) == 0 {
		return nil, internal.ErrNilArguments
	}

	// check duplicates
	dups := make(map[uint32]bool)
	for _, id := range resharingParticipantIDs {
		if dups[id] {
			return nil, fmt.Errorf("duplicate resharing participant ID: %d", id)
		}
		dups[id] = true
	}

	feldman, err := sharing.NewFeldman(threshold, uint32(len(newParticipantIDs)), curve, newParticipantIDs...)
	if err != nil {
		return nil, err
	}

	return &Resharing{
		Threshold:               threshold,
		NewParticipantIDs:       newParticipantIDs,
		ResharingParticipantIDs: resharingParticipantIDs,
		curve:                   curve,
		feldman:                 feldman,
	}, nil
}
