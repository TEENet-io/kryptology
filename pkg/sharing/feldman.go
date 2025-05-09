//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	"fmt"
	"io"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
)

type FeldmanVerifier struct {
	Commitments []curves.Point
}

func (v FeldmanVerifier) Verify(share *ShamirShare) error {
	curve := curves.GetCurveByName(v.Commitments[0].CurveName())
	err := share.Validate(curve)
	if err != nil {
		return err
	}
	x := curve.Scalar.New(int(share.Id))
	i := curve.Scalar.One()
	rhs := v.Commitments[0]

	for j := 1; j < len(v.Commitments); j++ {
		i = i.Mul(x)
		rhs = rhs.Add(v.Commitments[j].Mul(i))
	}
	sc, _ := curve.Scalar.SetBytes(share.Value)
	lhs := v.Commitments[0].Generator().Mul(sc)

	if lhs.Equal(rhs) {
		return nil
	} else {
		return fmt.Errorf("not equal")
	}
}

type Feldman struct {
	Threshold, Limit uint32
	Curve            *curves.Curve
	IDs              []uint32
}

func NewFeldman(threshold, limit uint32, curve *curves.Curve, IDs ...uint32) (*Feldman, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold cannot be less than 2")
	}
	if limit > 255 {
		return nil, fmt.Errorf("cannot exceed 255 shares")
	}
	if curve == nil {
		return nil, fmt.Errorf("invalid curve")
	}

	if len(IDs) > 0 {
		if len(IDs) != int(limit) {
			return nil, fmt.Errorf("length of IDs must be equal to limit")
		}
		idMap := make(map[uint32]bool)
		for _, id := range IDs {
			if id == 0 {
				return nil, fmt.Errorf("id cannot be 0")
			}
			if idMap[id] {
				return nil, fmt.Errorf("duplicate id found: %d", id)
			}
			idMap[id] = true
		}
	}

	if len(IDs) == 0 {
		IDs = make([]uint32, limit)
		for i := range IDs {
			IDs[i] = uint32(i + 1)
		}
	}

	return &Feldman{threshold, limit, curve, IDs}, nil
}

func (f Feldman) Split(secret curves.Scalar, reader io.Reader) (*FeldmanVerifier, map[uint32]*ShamirShare, error) {
	if secret.IsZero() {
		return nil, nil, fmt.Errorf("invalid secret")
	}

	poly := new(Polynomial).Init(secret, f.Threshold, reader)
	shares := make(map[uint32]*ShamirShare, f.Limit)
	for _, id := range f.IDs {
		x := f.Curve.Scalar.New(int(id))
		shares[id] = &ShamirShare{
			Id:    id,
			Value: poly.Evaluate(x).Bytes(),
		}
	}

	verifier := new(FeldmanVerifier)
	verifier.Commitments = make([]curves.Point, f.Threshold)
	for i := range verifier.Commitments {
		verifier.Commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return verifier, shares, nil
}

func (f Feldman) LagrangeCoeffs(shares map[uint32]*ShamirShare) (map[uint32]curves.Scalar, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	identities := make([]uint32, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	return shamir.LagrangeCoeffs(identities)
}

func (f Feldman) Combine(shares ...*ShamirShare) (curves.Scalar, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	return shamir.Combine(shares...)
}

func (f Feldman) CombinePoints(shares ...*ShamirShare) (curves.Point, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	return shamir.CombinePoints(shares...)
}
