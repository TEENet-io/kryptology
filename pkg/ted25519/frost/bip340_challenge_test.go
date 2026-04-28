// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// SPDX-License-Identifier: Apache-2.0

package frost

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
)

// TestBIP340ChallengeDeriver_MatchesSpec verifies the challenge formula by
// recomputing it manually using the BIP-340 spec:
//
//	c = SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") ||
//	          R_x || P_x || msg) mod n
//
// We pick R and P deterministically (scalar*G) so the test is self-contained
// and doesn't depend on randomness.
func TestBIP340ChallengeDeriver_MatchesSpec(t *testing.T) {
	curve := curves.K256()

	// Two distinct fixed scalars → two distinct points.
	rScalar, err := curve.Scalar.SetBytes([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	require.NoError(t, err)
	pScalar, err := curve.Scalar.SetBytes([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	require.NoError(t, err)

	R := curve.ScalarBaseMult(rScalar)
	P := curve.ScalarBaseMult(pScalar)
	msg := []byte("BIP340 challenge derivation smoke test")

	got, err := BIP340ChallengeDeriver{}.DeriveChallenge(msg, P, R)
	require.NoError(t, err)

	// Recompute c manually using the BIP-340 tagged hash construction.
	tag := sha256.Sum256([]byte("BIP0340/challenge"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	rCompressed := R.ToAffineCompressed()
	pCompressed := P.ToAffineCompressed()
	require.Equal(t, 33, len(rCompressed))
	require.Equal(t, 33, len(pCompressed))
	h.Write(rCompressed[1:])
	h.Write(pCompressed[1:])
	h.Write(msg)
	// BIP-340 uses big-endian int_from_bytes; route through big.Int + SetBigInt
	// because ScalarK256.SetBytes interprets little-endian internally.
	expected, err := new(curves.ScalarK256).SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))
	require.NoError(t, err)

	require.True(t, got.Cmp(expected) == 0,
		"challenge mismatch:\n  got  = %s\n  want = %s",
		hex.EncodeToString(got.Bytes()), hex.EncodeToString(expected.Bytes()))
}

// TestBIP340ChallengeDeriver_DiffersFromLegacy makes sure the new deriver
// is not accidentally equivalent to the existing Secp256k1ChallengeDeriver
// — they differ in tagged-hash prefix and x-only encoding, so the outputs
// must not coincidentally collide on a random input.
func TestBIP340ChallengeDeriver_DiffersFromLegacy(t *testing.T) {
	curve := curves.K256()
	rScalar, err := curve.Scalar.SetBytes([]byte("00000000000000000000000000000001"))
	require.NoError(t, err)
	pScalar, err := curve.Scalar.SetBytes([]byte("00000000000000000000000000000002"))
	require.NoError(t, err)
	R := curve.ScalarBaseMult(rScalar)
	P := curve.ScalarBaseMult(pScalar)
	msg := []byte("hello")

	bip, err := BIP340ChallengeDeriver{}.DeriveChallenge(msg, P, R)
	require.NoError(t, err)
	legacy, err := Secp256k1ChallengeDeriver{}.DeriveChallenge(msg, P, R)
	require.NoError(t, err)
	require.False(t, bip.Cmp(legacy) == 0, "BIP-340 and legacy derivers must differ")
}
