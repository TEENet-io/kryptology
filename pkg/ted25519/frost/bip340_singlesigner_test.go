// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// SPDX-License-Identifier: Apache-2.0

package frost

import (
	"crypto/rand"
	"testing"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestBIP340_SingleSignerAgreesWithBtcec runs a *plain* (non-FROST)
// Schnorr sign using BIP340ChallengeDeriver — no DKG, no aggregation,
// no R-parity flip — and checks that btcec/schnorr.Verify accepts it.
// If this fails the deriver is wrong; if it passes, the bug is on the
// FROST side (R parity, key normalisation, or share aggregation).
func TestBIP340_SingleSignerAgreesWithBtcec(t *testing.T) {
	curve := curves.K256()

	// Generate a private key x and pub P = x*G; force P to even Y.
	x := curve.Scalar.Random(rand.Reader)
	P := curve.ScalarBaseMult(x)
	if P.ToAffineCompressed()[0] != 0x02 {
		// odd Y: negate x and P together so P now has even Y.
		x = x.Neg()
		P = P.Neg()
	}
	require.Equal(t, byte(0x02), P.ToAffineCompressed()[0])

	// Generate a nonce k and R = k*G; force R to even Y.
	k := curve.Scalar.Random(rand.Reader)
	R := curve.ScalarBaseMult(k)
	if R.ToAffineCompressed()[0] != 0x02 {
		k = k.Neg()
		R = R.Neg()
	}
	require.Equal(t, byte(0x02), R.ToAffineCompressed()[0])

	msg := make([]byte, 32)
	_, _ = rand.Read(msg)

	c, err := BIP340ChallengeDeriver{}.DeriveChallenge(msg, P, R)
	require.NoError(t, err)

	// s = k + c*x
	s := c.Mul(x).Add(k)

	rxOnly := R.ToAffineCompressed()[1:]
	pxOnly := P.ToAffineCompressed()[1:]
	sig := append(append([]byte{}, rxOnly...), s.Bytes()...)
	require.Equal(t, 64, len(sig))

	pub, err := schnorr.ParsePubKey(pxOnly)
	require.NoError(t, err, "btcec rejected pubkey")
	parsed, err := schnorr.ParseSignature(sig)
	require.NoError(t, err, "btcec rejected signature parse")
	require.True(t, parsed.Verify(msg, pub),
		"btcec rejected a single-signer BIP-340 signature\n"+
			"  pub  = %x\n  R_x  = %x\n  s    = %x\n  msg  = %x",
		pxOnly, rxOnly, s.Bytes(), msg)
}
