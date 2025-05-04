//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package frost is an implementation of the DKG part of  https://eprint.iacr.org/2020/852.pdf
package frost

import (
	"strconv"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type DkgParticipant struct {
	round                  int
	Curve                  *curves.Curve
	otherParticipantShares map[uint32]*dkgParticipantData
	Id                     uint32
	SkShare                curves.Scalar
	VerificationKey        curves.Point
	VkShare                curves.Point

	// Public verification polynomial F(x) = f(x) * G, s.t.,
	//   f(0) == sk (hidden private key)
	//   Commitments[0] == F(0) == VerificationKey (public key)
	//	 SkShare * G = \sum_{j=0}^{threshold-1} Commitments[j] * Id^j
	Commitments []curves.Point
	Threshold   uint32

	feldman      *sharing.Feldman
	verifiers    *sharing.FeldmanVerifier
	secretShares map[uint32]*sharing.ShamirShare
	ctx          byte
}
type dkgParticipantData struct {
	Id        uint32
	Share     *sharing.ShamirShare
	Verifiers *sharing.FeldmanVerifier
}

func NewDkgParticipant(id, threshold uint32, ctx string, curve *curves.Curve, otherParticipants ...uint32) (*DkgParticipant, error) {
	if curve == nil || len(otherParticipants) == 0 {
		return nil, internal.ErrNilArguments
	}

	limit := uint32(len(otherParticipants)) + 1

	feldman, err := sharing.NewFeldman(threshold, limit, curve, append(otherParticipants, id)...)
	if err != nil {
		return nil, err
	}

	otherParticipantShares := make(map[uint32]*dkgParticipantData, len(otherParticipants))
	for _, id := range otherParticipants {
		otherParticipantShares[id] = &dkgParticipantData{
			Id: id,
		}
	}

	// SetBigInt the common fixed string
	ctxV, _ := strconv.Atoi(ctx)

	return &DkgParticipant{
		Id:                     id,
		round:                  1,
		Curve:                  curve,
		Threshold:              threshold,
		feldman:                feldman,
		otherParticipantShares: otherParticipantShares,
		ctx:                    byte(ctxV),
	}, nil
}

func (dp *DkgParticipant) Limit() uint32 {
	if dp == nil || dp.Curve == nil {
		return 0
	}
	return uint32(len(dp.otherParticipantShares) + 1)
}

func (dp *DkgParticipant) Ids() []uint32 {
	if dp == nil || dp.Curve == nil {
		return nil
	}
	ids := make([]uint32, 0, len(dp.otherParticipantShares)+1)
	ids = append(ids, dp.Id)
	for id := range dp.otherParticipantShares {
		ids = append(ids, id)
	}
	return ids
}

func EvalCommitmentPoly(curve *curves.Curve, coefs []curves.Point, x curves.Scalar) (curves.Point, error) {
	degree := len(coefs) - 1

	out, err := curve.Point.FromAffineCompressed(coefs[degree].ToAffineCompressed())
	if err != nil {
		return nil, err
	}

	for i := degree - 1; i >= 0; i-- {
		out = out.Mul(x).Add(coefs[i])
	}

	return out, nil
}
