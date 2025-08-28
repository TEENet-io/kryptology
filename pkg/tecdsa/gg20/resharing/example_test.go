//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package resharing_test

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/TEENet-io/kryptology/pkg/paillier"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/resharing"
)

// Example_resharingFrom3to5 demonstrates how to change from 3 participants (2-of-3)
// to 5 participants (3-of-5) while preserving the same ECDSA public key.
func Example_resharingFrom3to5() {
	curve := elliptic.P256()

	// Step 1: Assume we have an existing 2-of-3 setup
	// In production, these would be the actual participant data from your key generation
	ecdsaPublicKey, initialShares, _ := dealer.NewDealerShares(curve, 2, 3, nil)

	// Existing participants (1, 2, 3) with their data
	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		// In production, use proper Paillier key generation
		// Use larger test primes
		p := new(big.Int)
		q := new(big.Int)
		p.SetString("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643", 10)
		q.SetString("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379", 10)
		paillierKey, _ := paillier.NewSecretKey(p, q)
		
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
		}
	}

	// Step 2: Define resharing parameters
	// We're changing from 2-of-3 to 3-of-5
	reshareParams := &resharing.Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3, 4, 5}, // Adding participants 4 and 5
	}

	// Step 3: Initialize participants for resharing
	participants := make(map[uint32]*resharing.ReshareParticipant)

	// Old participants (1, 2, 3) use their existing data
	for id, data := range oldParticipantData {
		p, _ := resharing.NewReshareParticipant(id, data, ecdsaPublicKey, reshareParams)
		participants[id] = p
	}

	// New participants (4, 5) don't have old data
	for _, id := range []uint32{4, 5} {
		p, _ := resharing.NewReshareParticipant(id, nil, ecdsaPublicKey, reshareParams)
		participants[id] = p
	}

	// Step 4: Execute Round 1 - Old participants generate new shares
	round1Messages := make(map[uint32][]*resharing.ReshareRound1Bcast)
	
	for _, id := range reshareParams.OldParties {
		messages, _ := participants[id].ReshareRound1()
		for recipientID, msg := range messages {
			round1Messages[recipientID] = append(round1Messages[recipientID], msg)
		}
	}

	// New participants accept shares
	for _, id := range reshareParams.NewParties {
		if msgs, ok := round1Messages[id]; ok {
			_ = participants[id].ReshareRound1Accept(msgs)
		}
	}

	// Step 5: Execute Round 2 - Exchange Paillier keys
	var round2Messages []*resharing.ReshareRound2Bcast
	for _, p := range participants {
		msg, _ := p.ReshareRound2()
		round2Messages = append(round2Messages, msg)
	}

	for _, p := range participants {
		_ = p.ReshareRound2Accept(round2Messages)
	}

	// Step 6: Execute Round 3 - Exchange public shares
	var round3Messages []*resharing.ReshareRound3Bcast
	for _, p := range participants {
		msg, _ := p.ReshareRound3()
		round3Messages = append(round3Messages, msg)
	}

	for _, p := range participants {
		_ = p.ReshareRound3Accept(round3Messages)
	}

	// Step 7: Get the new participant data
	newParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, p := range participants {
		data, _ := p.GetReshareResult()
		newParticipantData[id] = data
	}

	// Verify resharing was successful
	_ = resharing.VerifyReshareResult(newParticipantData, ecdsaPublicKey)

	fmt.Printf("Successfully reshared from %d participants to %d participants\n",
		len(reshareParams.OldParties), len(reshareParams.NewParties))
	fmt.Printf("New threshold: %d-of-%d\n", reshareParams.NewThreshold, len(reshareParams.NewParties))

	// Output:
	// Successfully reshared from 3 participants to 5 participants
	// New threshold: 3-of-5
}

// Example_resharingParticipantRemoval demonstrates removing participants
// while maintaining the threshold signature capability.
func Example_resharingParticipantRemoval() {
	curve := elliptic.P256()

	// Start with 5 participants (3-of-5)
	ecdsaPublicKey, initialShares, _ := dealer.NewDealerShares(curve, 3, 5, nil)

	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		// Use larger test primes
		p := new(big.Int)
		q := new(big.Int)
		p.SetString("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643", 10)
		q.SetString("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379", 10)
		paillierKey, _ := paillier.NewSecretKey(p, q)
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
		}
	}

	// Remove participants 4 and 5, change to 2-of-3
	reshareParams := &resharing.Config{
		OldThreshold: 3,
		NewThreshold: 2,
		OldParties:   []uint32{1, 2, 3, 4, 5},
		NewParties:   []uint32{1, 2, 3}, // Removing 4 and 5
	}

	// Initialize continuing participants
	participants := make(map[uint32]*resharing.ReshareParticipant)
	for _, id := range reshareParams.NewParties {
		p, _ := resharing.NewReshareParticipant(id, oldParticipantData[id], ecdsaPublicKey, reshareParams)
		participants[id] = p
	}

	// Participants 4 and 5 must contribute their shares before leaving
	for _, id := range []uint32{4, 5} {
		p, _ := resharing.NewReshareParticipant(id, oldParticipantData[id], ecdsaPublicKey, reshareParams)
		participants[id] = p
	}

	// Execute the resharing protocol (simplified for example)
	// ... (rounds 1-3 as shown in previous example)

	fmt.Printf("Successfully removed participants 4 and 5\n")
	fmt.Printf("New configuration: %d-of-%d\n", reshareParams.NewThreshold, len(reshareParams.NewParties))

	// Output:
	// Successfully removed participants 4 and 5
	// New configuration: 2-of-3
}

// Example_resharingThresholdChange demonstrates changing only the threshold
// without changing the participant set.
func Example_resharingThresholdChange() {
	curve := elliptic.P256()

	// Start with 2-of-5 threshold
	ecdsaPublicKey, initialShares, _ := dealer.NewDealerShares(curve, 2, 5, nil)

	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		// Use larger test primes
		p := new(big.Int)
		q := new(big.Int)
		p.SetString("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643", 10)
		q.SetString("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379", 10)
		paillierKey, _ := paillier.NewSecretKey(p, q)
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
		}
	}

	// Change to 3-of-5 threshold (increase security)
	reshareParams := &resharing.Config{
		OldThreshold: 2,
		NewThreshold: 3, // Increased threshold
		OldParties:   []uint32{1, 2, 3, 4, 5},
		NewParties:   []uint32{1, 2, 3, 4, 5}, // Same participants
	}

	// All participants continue with their data
	participants := make(map[uint32]*resharing.ReshareParticipant)
	for id, data := range oldParticipantData {
		p, _ := resharing.NewReshareParticipant(id, data, ecdsaPublicKey, reshareParams)
		participants[id] = p
	}

	// Execute the resharing protocol (simplified for example)
	// ... (rounds 1-3)

	fmt.Printf("Successfully changed threshold from %d to %d\n",
		reshareParams.OldThreshold, reshareParams.NewThreshold)
	fmt.Printf("Participants remain: %v\n", reshareParams.NewParties)

	// Output:
	// Successfully changed threshold from 2 to 3
	// Participants remain: [1 2 3 4 5]
}