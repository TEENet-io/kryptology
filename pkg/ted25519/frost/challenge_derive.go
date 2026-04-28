//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
)

type ChallengeDerive interface {
	DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error)
}

type Ed25519ChallengeDeriver struct{}

func (ed Ed25519ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	h := sha512.New()
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)
	return new(curves.ScalarEd25519).SetBytesWide(h.Sum(nil))
}

type Secp256k1ChallengeDeriver struct{}

// DeriveChallenge implements the FROST challenge derivation for secp256k1 using SHA-256.
func (d Secp256k1ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	h := sha256.New()
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)
	return new(curves.ScalarK256).SetBytes(h.Sum(nil))
}

// BIP340ChallengeDeriver implements the challenge derivation specified in
// BIP-340 (Bitcoin Schnorr Signatures). The challenge is:
//
//	c = int(tagged_hash("BIP0340/challenge", R_x || P_x || msg)) mod n
//
// where tagged_hash(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x) and
// R_x, P_x are the 32-byte big-endian x-coordinates of R and P. R and P
// must already have even Y when reaching this function — the FROST
// round-2 path negates R if needed (round2.go), and DKG callers must
// negate the share / verification key once when the group key has odd Y.
//
// Use this deriver instead of Secp256k1ChallengeDeriver when generating
// signatures for Bitcoin Taproot, Nostr, or any BIP-340 consumer.
type BIP340ChallengeDeriver struct{}

// bip340ChallengeTag is precomputed: SHA256("BIP0340/challenge"). The full
// tagged hash prepends this twice before the message-specific bytes.
var bip340ChallengeTag = sha256.Sum256([]byte("BIP0340/challenge"))

func (BIP340ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	rCompressed := r.ToAffineCompressed()
	pCompressed := pubKey.ToAffineCompressed()
	if len(rCompressed) != 33 || len(pCompressed) != 33 {
		return nil, fmt.Errorf("BIP340: expected 33-byte SEC1 compressed points (got R=%d, P=%d)", len(rCompressed), len(pCompressed))
	}

	h := sha256.New()
	_, _ = h.Write(bip340ChallengeTag[:])
	_, _ = h.Write(bip340ChallengeTag[:])
	_, _ = h.Write(rCompressed[1:]) // strip parity byte → 32-byte x-only
	_, _ = h.Write(pCompressed[1:]) // strip parity byte → 32-byte x-only
	_, _ = h.Write(msg)
	// BIP-340 specifies int_from_bytes(...) as a big-endian integer reduction,
	// but ScalarK256.SetBytes uses the FROST internal little-endian convention
	// (see ReverseScalarBytes in core/curves/k256_curve.go). Going via big.Int
	// gives us the spec-compliant big-endian interpretation.
	return new(curves.ScalarK256).SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))
}
