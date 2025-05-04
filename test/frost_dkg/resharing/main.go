package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/coinbase/kryptology/internal"
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
	minId        = 1
	maxId        = 10000
)

func main() {
	participants, ids := createDkgParticipants(oldThreshold, oldLimit)

	fmt.Printf("**FROST DKG Round 1**\n")
	rnd1Bcast, rnd1P2p := round1(participants)
	fmt.Printf("**FROST DKG Round 2**\n")
	round2(participants, rnd1Bcast, rnd1P2p)

	newParticipants, newParticipantIDs := createDkgParticipants(newThreshold, newLimit)
	resharingParticipantIDs := ids[:newThreshold]
	r, err := dkg.NewResharing(uint32(newThreshold), testCurve, resharingParticipantIDs, newParticipantIDs)
	if err != nil {
		panic(err)
	}

	fmt.Printf("**Resharing Round 1**\n")
	bcast, p2psend := resharingRound1(r, participants)
	fmt.Printf("**Resharing Round 2**\n")
	resharingRound2(r, newParticipants, bcast, p2psend)

	// Check public keys
	pub := participants[ids[0]].VerificationKey
	for _, p := range newParticipants {
		if !p.VerificationKey.Equal(pub) {
			panic("invalid verification key")
		}
	}

	signerIds := newParticipantIDs[:newThreshold]
	lCoeffs := getLarangeCoeffs(testCurve, signerIds)
	signers := getFrostSigner(newParticipants, lCoeffs, signerIds)

	fmt.Printf("**Frost Sign Message**\n")
	results := frostSign(signers, msg, signerIds)

	// Verify signature
	pk := participants[ids[0]].VerificationKey.ToAffineCompressed()
	for _, id := range signerIds {
		R := results[id].R.ToAffineCompressed()
		Z := results[id].Z.Bytes()
		if !verify(msg, R, Z, pk) {
			panic("signature verification failed")
		}
	}
	fmt.Print("**Frost Signatures Verified**\n")
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
) map[uint32]*frost.Signer {
	var err error

	signers := make(map[uint32]*frost.Signer, len(signerIds))
	for _, id := range signerIds {
		signers[id], err = frost.NewSigner(participants[id], id, participants[id].Threshold, lCoeffs, signerIds, &frost.Ed25519ChallengeDeriver{})
		if err != nil {
			panic(err)
		}
	}

	return signers
}

func getLarangeCoeffs(
	curve *curves.Curve,
	Xs []uint32,
) map[uint32]curves.Scalar {
	dummyThreshold := 2
	dummyLimit := 2

	scheme, _ := sharing.NewShamir(uint32(dummyThreshold), uint32(dummyLimit), curve)

	lCoeffs, err := scheme.LagrangeCoeffs(Xs)
	if err != nil {
		panic(err)
	}

	return lCoeffs
}

func frostSign(
	signers map[uint32]*frost.Signer, msg []byte, signerIds []uint32,
) map[uint32]*frost.Round3Bcast {

	// fmt.Printf("**FROST Sign Round 1**\n")
	round2Input := make(map[uint32]*frost.Round1Bcast, len(signers))
	for _, id := range signerIds {
		// fmt.Printf("Computing Sign Round 1 for cosigner %d\n", i)
		round1Out, err := signers[id].SignRound1()
		if err != nil {
			panic(err)
		}
		round2Input[id] = round1Out
	}

	// Running sign round 2
	// fmt.Printf("**FROST Sign Round 2**\n")
	round3Input := make(map[uint32]*frost.Round2Bcast, len(signers))
	for _, id := range signerIds {
		// fmt.Printf("Computing Sign Round 2 for cosigner %d\n", i)
		round2Out, err := signers[id].SignRound2(msg, round2Input)
		if err != nil {
			panic(err)
		}
		round3Input[id] = round2Out
	}

	// Running sign round 3
	// fmt.Printf("**FROST Sign Round 3**\n")
	result := make(map[uint32]*frost.Round3Bcast, len(signers))
	for _, id := range signerIds {
		// fmt.Printf("Computing Sign Round 3 for cosigner %d\n", i)
		round3Out, err := signers[id].SignRound3(round3Input)
		if err != nil {
			panic(err)
		}
		result[id] = round3Out
	}
	return result
}

func resharingRound2(
	r *dkg.Resharing,
	newParticipants map[uint32]*dkg.DkgParticipant,
	bcastRnd1Out map[uint32]*dkg.ResharingBcast,
	p2pRnd1Out map[uint32]dkg.ResharingP2PSend,
) {
	S := r.ResharingParticipantIDs

	// Perform round 2
	for id, p := range newParticipants {
		// prepare p2psend for p
		p2pRnd2In := make(map[uint32]*sharing.ShamirShare, len(S))
		for _, i := range S {
			p2pRnd2In[i] = p2pRnd1Out[i][id]
		}

		err := r.ResharingRound2(p, bcastRnd1Out, p2pRnd2In)
		if err != nil {
			panic(err)
		}
	}
}

func resharingRound1(
	r *dkg.Resharing, participants map[uint32]*dkg.DkgParticipant,
) (map[uint32]*dkg.ResharingBcast, map[uint32]dkg.ResharingP2PSend) {
	var err error

	p2psend := make(map[uint32]dkg.ResharingP2PSend, len(r.ResharingParticipantIDs))
	bcast := make(map[uint32]*dkg.ResharingBcast, len(r.ResharingParticipantIDs))

	for _, id := range r.ResharingParticipantIDs {
		bcast[id], p2psend[id], err = r.ResharingRound1(participants[id])
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

func createDkgParticipants(thresh, limit int) (map[uint32]*dkg.DkgParticipant, []uint32) {
	participants := make(map[uint32]*dkg.DkgParticipant, limit)

	IDs, _ := internal.SampleUniqueUint32s(limit, minId, maxId)

	for _, i := range IDs {
		otherIds := make([]uint32, 0, limit-1)
		for _, j := range IDs {
			if i == j {
				continue
			}
			otherIds = append(otherIds, j)
		}
		p, err := dkg.NewDkgParticipant(i, uint32(thresh), ctx, testCurve, otherIds...)
		if err != nil {
			panic(err)
		}
		participants[i] = p
	}
	return participants, IDs
}
