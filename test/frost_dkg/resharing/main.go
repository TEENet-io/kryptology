package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

var (
	oldThreshold = 3
	oldLimit     = 5
	newThreshold = 4
	newLimit     = 7
	testCurve    = curves.ED25519()
	ctx          = "string to prevent replay attack"
	msg          = []byte("message to sign")
)

func main() {
	participants := createDkgParticipants(oldThreshold, oldLimit)

	fmt.Printf("**FROST DKG Round 1**\n")
	rnd1Bcast, rnd1P2p := round1(participants)
	fmt.Printf("**FROST DKG Round 2**\n")
	round2(participants, rnd1Bcast, rnd1P2p)

	resharingParticipants := createDkgParticipants(newThreshold, newLimit)

	fmt.Printf("**Resharing Round 1**\n")
	bcast, p2psend := resharingRound1(participants)
	fmt.Printf("**Resharing Round 2**\n")
	resharingRound2(resharingParticipants, bcast, p2psend, oldThreshold)

	// Check public keys
	pub := participants[1].VerificationKey
	for _, p := range resharingParticipants {
		if !p.VerificationKey.Equal(pub) {
			panic("invalid verification key")
		}
	}

	signerIds := make([]uint32, newThreshold)
	for i := 0; i < newThreshold; i++ {
		signerIds[i] = uint32(i + 1)
	}

	lCoeffs, err := getLarangeCoeffs(testCurve, signerIds)
	if err != nil {
		panic(err)
	}
	signers, err := getFrostSigner(resharingParticipants, lCoeffs, signerIds)
	if err != nil {
		panic(err)
	}
	fmt.Printf("**Frost Sign Message**\n")
	actual, err := frostSign(signers, msg, signerIds)
	if err != nil {
		panic(err)
	}

	// Verify signature
	R := actual[1].R.ToAffineCompressed()
	Z := actual[1].Z.Bytes()
	pk := participants[1].VerificationKey.ToAffineCompressed()
	if verify(msg, R, Z, pk) {
		fmt.Printf("Signature is valid\n")
	} else {
		fmt.Printf("Signature is invalid\n")
	}
}

func verify(msg []byte, R []byte, Z []byte, publicKey []byte) bool {
	pub := ed25519.PublicKey(publicKey)
	sig := append(R[:], Z[:]...)
	return ed25519.Verify(pub, msg, sig)
}

func getFrostSigner(
	participants map[uint32]*dkg.DkgParticipant,
	lCoeffs map[uint32]curves.Scalar,
	signerIds []uint32,
) (map[uint32]*frost.Signer, error) {
	var err error

	threshold := len(signerIds)

	signers := make(map[uint32]*frost.Signer, threshold)
	for i := 1; i <= threshold; i++ {
		signers[uint32(i)], err = frost.NewSigner(participants[uint32(i)], uint32(i), uint32(threshold), lCoeffs, signerIds, &frost.Ed25519ChallengeDeriver{})
		if err != nil {
			panic(err)
		}
	}

	return signers, nil
}

func getLarangeCoeffs(
	curve *curves.Curve,
	Xs []uint32,
) (map[uint32]curves.Scalar, error) {
	dummyThreshold := 2
	dummyLimit := 2

	scheme, _ := sharing.NewShamir(uint32(dummyThreshold), uint32(dummyLimit), curve)

	lCoeffs, err := scheme.LagrangeCoeffs(Xs)
	if err != nil {
		panic(err)
	}

	return lCoeffs, nil
}

func frostSign(
	signers map[uint32]*frost.Signer, msg []byte, signerIds []uint32,
) (map[uint32]*frost.Round3Bcast, error) {
	threshold := len(signerIds)

	// fmt.Printf("**FROST Sign Round 1**\n")
	round2Input := make(map[uint32]*frost.Round1Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		// fmt.Printf("Computing Sign Round 1 for cosigner %d\n", i)
		round1Out, err := signers[uint32(i)].SignRound1()
		if err != nil {
			panic(err)
		}
		round2Input[uint32(i)] = round1Out
	}

	// Running sign round 2
	// fmt.Printf("**FROST Sign Round 2**\n")
	round3Input := make(map[uint32]*frost.Round2Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		// fmt.Printf("Computing Sign Round 2 for cosigner %d\n", i)
		round2Out, err := signers[uint32(i)].SignRound2(msg, round2Input)
		if err != nil {
			panic(err)
		}
		round3Input[uint32(i)] = round2Out
	}

	// Running sign round 3
	// fmt.Printf("**FROST Sign Round 3**\n")
	result := make(map[uint32]*frost.Round3Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		// fmt.Printf("Computing Sign Round 3 for cosigner %d\n", i)
		round3Out, err := signers[uint32(i)].SignRound3(round3Input)
		if err != nil {
			panic(err)
		}
		result[uint32(i)] = round3Out
	}
	return result, nil
}

func resharingRound2(
	resharingParticipants map[uint32]*dkg.DkgParticipant,
	bcast map[uint32]*dkg.ResharingBcast,
	p2psend map[uint32]dkg.ResharingP2PSend,
	oldThreshold int,
) {
	S := make([]uint32, 0, len(bcast))
	for id := range bcast {
		S = append(S, id)
	}

	// Perform round 2
	for id, p := range resharingParticipants {
		// prepare p2psend for p
		p2p := make(map[uint32]*sharing.ShamirShare, len(S))
		for _, i := range S {
			p2p[i] = p2psend[i][id]
		}

		err := p.ResharingRound2(oldThreshold, bcast, p2p)
		if err != nil {
			panic(err)
		}
	}
}

func resharingRound1(
	participants map[uint32]*dkg.DkgParticipant,
) (map[uint32]*dkg.ResharingBcast, map[uint32]dkg.ResharingP2PSend) {
	var err error

	p2psend := make(map[uint32]dkg.ResharingP2PSend, len(participants))
	bcast := make(map[uint32]*dkg.ResharingBcast, len(participants))

	newParticipants := make([]uint32, newLimit)
	for i := 1; i <= newLimit; i++ {
		newParticipants[i-1] = uint32(i)
	}
	for _, p := range participants {
		id := p.Id
		bcast[id], p2psend[id], err = p.ResharingRound1(newThreshold, newParticipants...)
		if err != nil {
			panic(err)
		}
	}

	return bcast, p2psend
}

func round1(participants map[uint32]*dkg.DkgParticipant) (map[uint32]*dkg.Round1Bcast, map[uint32]dkg.Round1P2PSend) {
	// DKG Round 1
	rnd1Bcast := make(map[uint32]*dkg.Round1Bcast, len(participants))
	rnd1P2p := make(map[uint32]dkg.Round1P2PSend, len(participants))
	for id, p := range participants {
		// fmt.Printf("Computing DKG Round 1 for participant %d\n", id)
		bcast, p2psend, err := p.Round1(nil)
		if err != nil {
			panic(err)
		}
		rnd1Bcast[id] = bcast
		rnd1P2p[id] = p2psend
	}
	return rnd1Bcast, rnd1P2p
}

func round2(participants map[uint32]*dkg.DkgParticipant,
	rnd1Bcast map[uint32]*dkg.Round1Bcast,
	rnd1P2p map[uint32]dkg.Round1P2PSend,
) {
	for id := range rnd1Bcast {
		// fmt.Printf("Computing DKG Round 2 for participant %d\n", id)
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd1P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd1P2p[jid][id]
		}
		_, err := participants[id].Round2(rnd1Bcast, rnd1P2pForP)
		if err != nil {
			panic(err)
		}
	}
	return
}

func createDkgParticipants(thresh, limit int) map[uint32]*dkg.DkgParticipant {
	participants := make(map[uint32]*dkg.DkgParticipant, limit)
	for i := 1; i <= limit; i++ {
		otherIds := make([]uint32, limit-1)
		idx := 0
		for j := 1; j <= limit; j++ {
			if i == j {
				continue
			}
			otherIds[idx] = uint32(j)
			idx++
		}
		p, err := dkg.NewDkgParticipant(uint32(i), uint32(thresh), ctx, testCurve, otherIds...)
		if err != nil {
			panic(err)
		}
		participants[uint32(i)] = p
	}
	return participants
}
