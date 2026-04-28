// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// SPDX-License-Identifier: Apache-2.0

package frost

import (
	"crypto/rand"
	"testing"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
	dkg "github.com/TEENet-io/kryptology/pkg/dkg/frost"
	"github.com/TEENet-io/kryptology/pkg/sharing"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestBIP340_KryptologyAndBtcecAgree runs a full FROST DKG + sign on
// secp256k1 using BIP340ChallengeDeriver, then verifies the result with
// both kryptology's own Verify and btcec/schnorr.Verify (BIP-340). Any
// disagreement is a bug in the deriver / DKG normalisation / R-parity
// flip path.
func TestBIP340_KryptologyAndBtcecAgree(t *testing.T) {
	curve := curves.K256()
	threshold := uint32(2)
	limit := uint32(3)

	// --- DKG ---
	parts := make(map[uint32]*dkg.DkgParticipant, limit)
	for id := uint32(1); id <= limit; id++ {
		others := []uint32{}
		for j := uint32(1); j <= limit; j++ {
			if j != id {
				others = append(others, j)
			}
		}
		p, err := dkg.NewDkgParticipant(id, threshold, "test-ctx", curve, others...)
		require.NoError(t, err)
		parts[id] = p
	}

	round1Out := make(map[uint32]map[uint32]*sharing.ShamirShare, limit)
	round1Bcast := make(map[uint32]*dkg.Round1Bcast, limit)
	for id, p := range parts {
		bcast, p2p, err := p.Round1(nil)
		require.NoError(t, err)
		round1Bcast[id] = bcast
		round1Out[id] = p2p
	}

	for id, p := range parts {
		// peer broadcast and p2p inputs (excluding self)
		peerBcast := make(map[uint32]*dkg.Round1Bcast)
		peerP2P := make(map[uint32]*sharing.ShamirShare)
		for j, b := range round1Bcast {
			if j == id {
				continue
			}
			peerBcast[j] = b
			peerP2P[j] = round1Out[j][id]
		}
		_, err := p.Round2(peerBcast, peerP2P)
		require.NoError(t, err)
	}

	vk := parts[1].VerificationKey
	require.NotNil(t, vk)

	// All participants must agree on the (now even-Y) verification key.
	vkCompressed := vk.ToAffineCompressed()
	require.Equal(t, byte(0x02), vkCompressed[0], "DKG should normalise group key to even Y")
	for id := uint32(2); id <= limit; id++ {
		require.True(t, parts[id].VerificationKey.Equal(vk), "participant %d disagrees on VK", id)
	}

	// --- Sign with t=threshold signers (use ids 1..threshold) ---
	signerIDs := make([]uint32, 0, threshold)
	for id := uint32(1); id <= threshold; id++ {
		signerIDs = append(signerIDs, id)
	}

	scheme, err := sharing.NewShamir(threshold, limit, curve)
	require.NoError(t, err)
	lcoeffs, err := scheme.LagrangeCoeffs(signerIDs)
	require.NoError(t, err)

	signers := make(map[uint32]*Signer, threshold)
	for _, id := range signerIDs {
		s, err := NewSigner(parts[id], id, threshold, lcoeffs, signerIDs, BIP340ChallengeDeriver{})
		require.NoError(t, err)
		signers[id] = s
	}

	r1 := make(map[uint32]*Round1Bcast, threshold)
	for id, s := range signers {
		bcast, err := s.SignRound1()
		require.NoError(t, err)
		r1[id] = bcast
	}

	msg := make([]byte, 32)
	_, _ = rand.Read(msg)

	r2 := make(map[uint32]*Round2Bcast, threshold)
	for id, s := range signers {
		bcast, err := s.SignRound2(msg, r1)
		require.NoError(t, err)
		r2[id] = bcast
	}

	r3 := make(map[uint32]*Round3Bcast, threshold)
	for id, s := range signers {
		bcast, err := s.SignRound3(r2)
		require.NoError(t, err)
		r3[id] = bcast
	}

	// All r3.R / r3.Z must be identical across signers.
	var (
		sigR = r3[signerIDs[0]].R
		sigZ = r3[signerIDs[0]].Z
		sigC = r3[signerIDs[0]].C
	)
	for _, id := range signerIDs[1:] {
		require.True(t, r3[id].R.Equal(sigR), "Rs disagree across signers")
		require.Equal(t, 0, r3[id].Z.Cmp(sigZ), "Zs disagree across signers")
		require.Equal(t, 0, r3[id].C.Cmp(sigC), "Cs disagree across signers")
	}

	// Kryptology Verify (uses our deriver) — must accept.
	ok, err := Verify(curve, BIP340ChallengeDeriver{}, vk, msg, &Signature{Z: sigZ, C: sigC})
	require.NoError(t, err)
	require.True(t, ok, "kryptology BIP-340 verify rejected its own signature")

	// btcec/schnorr Verify (independent BIP-340 implementation) — must accept.
	rxOnly := sigR.ToAffineCompressed()[1:]
	pxOnly := vkCompressed[1:]
	sig := append(append([]byte{}, rxOnly...), sigZ.Bytes()...)
	require.Equal(t, 64, len(sig))

	pub, err := schnorr.ParsePubKey(pxOnly)
	require.NoError(t, err, "btcec rejected pubkey")
	parsed, err := schnorr.ParseSignature(sig)
	require.NoError(t, err, "btcec rejected signature parse")
	// Independent BIP-340 challenge computation (matches what btcec uses).
	indep, err := BIP340ChallengeDeriver{}.DeriveChallenge(msg, vk, sigR)
	require.NoError(t, err)
	cFromSign := sigC.Bytes()
	cIndep := indep.Bytes()
	rParityByte := sigR.ToAffineCompressed()[0]
	pParityByte := vkCompressed[0]
	require.True(t, parsed.Verify(msg, pub),
		"btcec/schnorr.Verify rejected a kryptology BIP-340 FROST signature\n"+
			"  pub        = %x  (parity=%02x)\n  R_x        = %x  (parity=%02x)\n  s          = %x\n  msg        = %x\n  c (sign)   = %x\n  c (indep)  = %x\n  c match    = %v",
		pxOnly, pParityByte, rxOnly, rParityByte, sigZ.Bytes(), msg, cFromSign, cIndep, sigC.Cmp(indep) == 0)
}
