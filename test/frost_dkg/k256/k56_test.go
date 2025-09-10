package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/sharing"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestK256(t *testing.T) {
	threshold := 2
	limit := 4

	// DEMO doing FROST DKG and that signers can compute a signature
	participants := createDkgParticipants(threshold, limit)

	// DKG Round 1
	rnd1Bcast, rnd1P2p := round1(participants)

	// DKG Round 2
	verificationKey, signingShares := round2(participants, rnd1Bcast, rnd1P2p)

	// Signing common setup for all participants
	curve := curves.K256()
	msg := []byte("All my bitcoin is stored here")
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	shares := make([]*sharing.ShamirShare, 0, threshold)
	cnt := 0
	for _, share := range signingShares {
		if cnt == threshold {
			break
		}
		cnt++
		shares = append(shares, share)
	}
	sk, err := scheme.Combine(shares...)
	if err != nil {
		panic(err)
	}

	pk := curve.ScalarBaseMult(sk)
	if !pk.Equal(verificationKey) {
		panic("verification keys are not equal")
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(sk.Bytes())
	hBytes := sha512.Sum384(msg)
	hMsg := new(big.Int).SetBytes(hBytes[:])
	hMsg.Mod(hMsg, btcec.S256().N)

	r, s, err := ecdsa.Sign(crand.Reader, privKey.ToECDSA(), hMsg.Bytes())
	if err != nil {
		panic(err)
	}
	ok := ecdsa.Verify(pubKey.ToECDSA(), hMsg.Bytes(), r, s)
	fmt.Printf("Signature verification - %v\n", ok)
}
