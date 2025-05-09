//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
)

var testCurve = curves.ED25519()

func TestEd25519FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := NewFeldman(0, 0, testCurve)
	require.NotNil(t, err)
	_, err = NewFeldman(3, 2, testCurve)
	require.NotNil(t, err)
	_, err = NewFeldman(1, 10, testCurve)
	require.NotNil(t, err)
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, _, err = scheme.Split(testCurve.NewScalar(), crand.Reader)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineNoShares(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*ShamirShare{
		{
			Id:    1,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
		{
			Id:    1,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
	}...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	shares := []*ShamirShare{
		{
			Id:    0,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
		{
			Id:    2,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineSingleWithDefaultIds(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shareMap, err := scheme.Split(secret, crand.Reader)
	require.Nil(t, err)
	require.NotNil(t, shareMap)
	for _, s := range shareMap {
		err = verifiers.Verify(s)
		require.Nil(t, err)
	}

	shares := make([]*ShamirShare, 0, len(shareMap))
	for _, s := range shareMap {
		shares = append(shares, s)
	}

	secret2, err := scheme.Combine(shares...)
	require.Nil(t, err)
	require.Equal(t, secret2, secret)
}

func TestEd25519FeldmanAllCombinations(t *testing.T) {
	IDs, _ := internal.SampleUniqueUint32s(5, 1, 100)

	scheme, err := NewFeldman(3, 5, testCurve, IDs...)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shares, err := scheme.Split(secret, crand.Reader)
	for _, s := range shares {
		err = verifiers.Verify(s)
		require.Nil(t, err)
	}
	require.Nil(t, err)
	require.NotNil(t, shares)

	// There are 5*4*3 possible combinations
	for _, i := range IDs {
		for _, j := range IDs {
			if i == j {
				continue
			}
			for _, k := range IDs {
				if i == k || j == k {
					continue
				}

				rSecret, err := scheme.Combine(shares[i], shares[j], shares[k])
				require.Nil(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret, secret)
			}
		}
	}
}
