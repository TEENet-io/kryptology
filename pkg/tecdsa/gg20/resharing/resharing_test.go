//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package resharing

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TEENet-io/kryptology/internal"
	"github.com/TEENet-io/kryptology/pkg/core/curves"
	"github.com/TEENet-io/kryptology/pkg/paillier"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/participant"
)

func generateTestPaillierKey() (*paillier.SecretKey, error) {
	// Use larger test primes that are still fast but large enough for ECDSA
	p := new(big.Int)
	q := new(big.Int)
	p.SetString("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643", 10)
	q.SetString("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379", 10)
	return paillier.NewSecretKey(p, q)
}

func TestIntegration_CompleteResharing(t *testing.T) {
	// Use P-256 curve
	curve := elliptic.P256()
	
	// Step 1: Generate initial shares (2-of-3)
	t.Log("Step 1: Generating initial ECDSA key shares (2-of-3)")
	ecdsaPublicKey, initialShares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(t, err)
	require.NotNil(t, ecdsaPublicKey)
	require.Len(t, initialShares, 3)
	
	t.Logf("Generated ECDSA public key: X=%s, Y=%s", 
		ecdsaPublicKey.X.Text(16), ecdsaPublicKey.Y.Text(16))
	
	// Prepare participant data for old participants
	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	publicShares, err := dealer.PreparePublicShares(initialShares)
	require.NoError(t, err)
	
	for id, share := range initialShares {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
			PublicShares:   publicShares,
			KeyGenType:     &dealer.TrustedDealerKeyGenType{},
			EncryptKeys:    make(map[uint32]*paillier.PublicKey),
		}
		
		// Add Paillier public keys
		for j := uint32(1); j <= 3; j++ {
			oldParticipantData[id].EncryptKeys[j] = &paillierKey.PublicKey
		}
	}
	
	// Step 2: Setup resharing parameters (2-of-3 -> 3-of-5)
	t.Log("Step 2: Setting up resharing from 2-of-3 to 3-of-5")
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3, 4, 5},
	}
	
	// Step 3: Create participants
	t.Log("Step 3: Creating resharing participants")
	participants := make(map[uint32]*ReshareParticipant)
	
	// Old participants (1, 2, 3)
	for id, data := range oldParticipantData {
		p, err := NewReshareParticipant(id, data, ecdsaPublicKey, params)
		require.NoError(t, err)
		participants[id] = p
		t.Logf("Created old participant %d", id)
	}
	
	// New participants (4, 5)
	for _, id := range []uint32{4, 5} {
		p, err := NewReshareParticipant(id, nil, ecdsaPublicKey, params)
		require.NoError(t, err)
		participants[id] = p
		t.Logf("Created new participant %d", id)
	}
	
	// Step 4: Execute resharing protocol
	t.Log("Step 4: Executing resharing protocol")
	executeTestResharing(t, participants, params)
	
	// Step 5: Get results and verify
	t.Log("Step 5: Getting results and verifying")
	newParticipantData := make(map[uint32]*dealer.ParticipantData)
	
	for id, p := range participants {
		result, err := p.GetReshareResult()
		require.NoError(t, err)
		newParticipantData[id] = result
		
		// Verify public key is preserved
		assert.Equal(t, ecdsaPublicKey.X, result.EcdsaPublicKey.X)
		assert.Equal(t, ecdsaPublicKey.Y, result.EcdsaPublicKey.Y)
		
		// Verify participant has required data
		assert.NotNil(t, result.SecretKeyShare)
		assert.NotNil(t, result.DecryptKey)
		assert.Len(t, result.PublicShares, 5)
		assert.Len(t, result.EncryptKeys, 5)
		
		t.Logf("Participant %d: Got valid resharing result", id)
	}
	
	// Step 6: Verify resharing was successful
	err = VerifyReshareResult(newParticipantData, ecdsaPublicKey)
	require.NoError(t, err)
	t.Log("✓ Resharing verification successful!")
	
	// Step 7: Test that we can create signers with new shares
	t.Log("Step 7: Testing signer creation with new shares")
	
	// Select 3 participants (threshold) for signing
	signerIDs := []uint32{1, 3, 5}
	signers := make([]*participant.Signer, 0, 3)
	
	for _, id := range signerIDs {
		data := newParticipantData[id]
		signer, err := participant.NewSigner(data, signerIDs)
		require.NoError(t, err)
		require.NotNil(t, signer)
		signers = append(signers, signer)
		t.Logf("Created signer for participant %d", id)
	}
	
	t.Log("✓ Successfully created signers with new shares!")
	t.Log("✓ Complete resharing test passed!")
}

func TestIntegration_ParticipantRemoval(t *testing.T) {
	curve := elliptic.P256()
	
	// Start with 5 participants (3-of-5)
	t.Log("Starting with 5 participants (3-of-5)")
	ecdsaPublicKey, initialShares, err := dealer.NewDealerShares(curve, 3, 5, nil)
	require.NoError(t, err)
	
	publicShares, err := dealer.PreparePublicShares(initialShares)
	require.NoError(t, err)
	
	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
			PublicShares:   publicShares,
			KeyGenType:     &dealer.TrustedDealerKeyGenType{},
			EncryptKeys:    make(map[uint32]*paillier.PublicKey),
		}
		
		for j := uint32(1); j <= 5; j++ {
			oldParticipantData[id].EncryptKeys[j] = &paillierKey.PublicKey
		}
	}
	
	// Reshare to remove participants 4 and 5 (3-of-5 -> 2-of-3)
	t.Log("Resharing to remove participants 4 and 5 (3-of-5 -> 2-of-3)")
	params := &Config{
		OldThreshold: 3,
		NewThreshold: 2,
		OldParties:   []uint32{1, 2, 3, 4, 5},
		NewParties:   []uint32{1, 2, 3},
	}
	
	// Create participants (including those who are leaving)
	participants := make(map[uint32]*ReshareParticipant)
	
	// All old participants need to participate
	for id, data := range oldParticipantData {
		p, err := NewReshareParticipant(id, data, ecdsaPublicKey, params)
		require.NoError(t, err)
		participants[id] = p
	}
	
	// Execute resharing protocol
	executeTestResharing(t, participants, params)
	
	// Get results (only for continuing participants)
	newParticipantData := make(map[uint32]*dealer.ParticipantData)
	for _, id := range params.NewParties {
		p := participants[id]
		result, err := p.GetReshareResult()
		require.NoError(t, err)
		newParticipantData[id] = result
	}
	
	// Verify
	err = VerifyReshareResult(newParticipantData, ecdsaPublicKey)
	require.NoError(t, err)
	assert.Len(t, newParticipantData, 3)
	
	t.Log("✓ Successfully removed participants 4 and 5!")
}

func TestIntegration_ThresholdChange(t *testing.T) {
	curve := elliptic.P256()
	
	// Start with 2-of-5 threshold
	t.Log("Starting with 2-of-5 threshold")
	ecdsaPublicKey, initialShares, err := dealer.NewDealerShares(curve, 2, 5, nil)
	require.NoError(t, err)
	
	oldParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldParticipantData[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: ecdsaPublicKey,
		}
	}
	
	// Change to 3-of-5 threshold (increase security)
	t.Log("Changing to 3-of-5 threshold")
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3, 4, 5},
		NewParties:   []uint32{1, 2, 3, 4, 5}, // Same participants
	}
	
	// All participants continue
	participants := make(map[uint32]*ReshareParticipant)
	for id, data := range oldParticipantData {
		p, err := NewReshareParticipant(id, data, ecdsaPublicKey, params)
		require.NoError(t, err)
		participants[id] = p
	}
	
	// Execute resharing
	executeTestResharing(t, participants, params)
	
	// Get results
	newParticipantData := make(map[uint32]*dealer.ParticipantData)
	for id, p := range participants {
		result, err := p.GetReshareResult()
		require.NoError(t, err)
		newParticipantData[id] = result
	}
	
	// Verify
	err = VerifyReshareResult(newParticipantData, ecdsaPublicKey)
	require.NoError(t, err)
	assert.Len(t, newParticipantData, 5)
	
	t.Logf("✓ Successfully changed threshold from %d to %d", params.OldThreshold, params.NewThreshold)
}

func TestResharing_InvalidParameters(t *testing.T) {
	curve := elliptic.P256()
	publicKey, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(t, err)

	t.Run("NilParams", func(t *testing.T) {
		_, err := NewReshareParticipant(1, nil, publicKey, nil)
		assert.Error(t, err)
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		params := &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		}
		_, err := NewReshareParticipant(1, nil, nil, params)
		assert.Error(t, err)
	})

	t.Run("IDMismatch", func(t *testing.T) {
		params := &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		}
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:         2, // Different from participant ID
			DecryptKey: paillierKey,
		}
		
		_, err = NewReshareParticipant(1, oldData, publicKey, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID mismatch")
	})
}

func TestResharing_RoundValidation(t *testing.T) {
	curve := elliptic.P256()
	publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(t, err)

	params := &Config{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3},
	}

	paillierKey, err := generateTestPaillierKey()
	require.NoError(t, err)

	oldData := &dealer.ParticipantData{
		Id:             1,
		SecretKeyShare: shares[1],
		DecryptKey:     paillierKey,
		EcdsaPublicKey: publicKey,
	}

	p, err := NewReshareParticipant(1, oldData, publicKey, params)
	require.NoError(t, err)

	t.Run("Round1OnlyForOldParticipants", func(t *testing.T) {
		// Create a new participant (no old share)
		newP, err := NewReshareParticipant(4, nil, publicKey, params)
		require.NoError(t, err)

		_, err = newP.ReshareRound1()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only old participants")
	})

	t.Run("InvalidRoundOrder", func(t *testing.T) {
		// Try to execute round 2 before round 1
		_, err := p.ReshareRound2()
		assert.Error(t, err)
	})

	t.Run("GetResultBeforeCompletion", func(t *testing.T) {
		_, err := p.GetReshareResult()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not complete")
	})
}

func TestResharing_ShareVerification(t *testing.T) {
	curve := elliptic.P256()
	publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(t, err)
	
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3},
	}
	
	// Create old participant
	paillierKey, err := generateTestPaillierKey()
	require.NoError(t, err)
	
	oldData := &dealer.ParticipantData{
		Id:             1,
		SecretKeyShare: shares[1],
		DecryptKey:     paillierKey,
		EcdsaPublicKey: publicKey,
	}
	
	p, err := NewReshareParticipant(1, oldData, publicKey, params)
	require.NoError(t, err)
	
	// Generate shares
	messages, err := p.ReshareRound1()
	require.NoError(t, err)
	
	// Verify that shares are correctly generated for all new participants
	assert.Len(t, messages, len(params.NewParties))
	for _, id := range params.NewParties {
		msg, ok := messages[id]
		assert.True(t, ok)
		assert.Equal(t, id, msg.ToID)
		assert.NotNil(t, msg.Share)
		assert.Len(t, msg.Commitments, int(params.NewThreshold))
	}
}

// Helper function to execute the full resharing protocol
func executeTestResharing(t *testing.T, participants map[uint32]*ReshareParticipant, params *Config) {
	// Round 1: Generate and distribute shares
	round1Messages := make(map[uint32][]*ReshareRound1Bcast)
	
	// ALL old participants must generate shares for proper public key preservation
	for _, id := range params.OldParties {
		if p, ok := participants[id]; ok && p.OldShare != nil {
			messages, err := p.ReshareRound1()
			require.NoError(t, err)
			
			for recipientID, msg := range messages {
				round1Messages[recipientID] = append(round1Messages[recipientID], msg)
			}
		}
	}

	// New participants accept shares
	for _, id := range params.NewParties {
		if msgs, ok := round1Messages[id]; ok {
			err := participants[id].ReshareRound1Accept(msgs)
			require.NoError(t, err)
		}
	}

	// Round 2: Exchange Paillier keys
	var round2Messages []*ReshareRound2Bcast
	for _, id := range params.NewParties {
		msg, err := participants[id].ReshareRound2()
		require.NoError(t, err)
		round2Messages = append(round2Messages, msg)
	}

	for _, id := range params.NewParties {
		err := participants[id].ReshareRound2Accept(round2Messages)
		require.NoError(t, err)
	}

	// Round 3: Share public shares
	var round3Messages []*ReshareRound3Bcast
	for _, id := range params.NewParties {
		msg, err := participants[id].ReshareRound3()
		require.NoError(t, err)
		round3Messages = append(round3Messages, msg)
	}

	for _, id := range params.NewParties {
		err := participants[id].ReshareRound3Accept(round3Messages)
		require.NoError(t, err)
	}
}

// Benchmark tests

func BenchmarkResharing_3to5(b *testing.B) {
	curve := elliptic.P256()
	
	// Setup initial shares
	publicKey, initialShares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(b, err)
	
	oldParticipants := make(map[uint32]*dealer.ParticipantData)
	for id, share := range initialShares {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(b, err)
		
		oldParticipants[id] = &dealer.ParticipantData{
			Id:             id,
			SecretKeyShare: share,
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
	}
	
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3, 4, 5},
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Initialize participants
		participants := make(map[uint32]*ReshareParticipant)
		
		for id, oldData := range oldParticipants {
			p, _ := NewReshareParticipant(id, oldData, publicKey, params)
			participants[id] = p
		}
		
		for _, id := range []uint32{4, 5} {
			p, _ := NewReshareParticipant(id, nil, publicKey, params)
			participants[id] = p
		}
		
		// Execute resharing (simplified for benchmark)
		// Round 1
		round1Messages := make(map[uint32][]*ReshareRound1Bcast)
		for _, id := range params.OldParties {
			if messages, err := participants[id].ReshareRound1(); err == nil {
				for recipientID, msg := range messages {
					round1Messages[recipientID] = append(round1Messages[recipientID], msg)
				}
			}
		}
		for _, id := range params.NewParties {
			if msgs, ok := round1Messages[id]; ok {
				_ = participants[id].ReshareRound1Accept(msgs)
			}
		}
	}
}

func BenchmarkResharing_Round1(b *testing.B) {
	curve := elliptic.P256()
	publicKey, shares, _ := dealer.NewDealerShares(curve, 2, 3, nil)
	
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3, 4, 5},
	}
	
	paillierKey, _ := generateTestPaillierKey()
	oldData := &dealer.ParticipantData{
		Id:             1,
		SecretKeyShare: shares[1],
		DecryptKey:     paillierKey,
		EcdsaPublicKey: publicKey,
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		p, _ := NewReshareParticipant(1, oldData, publicKey, params)
		_, _ = p.ReshareRound1()
	}
}

func BenchmarkVerifyFeldmanShare(b *testing.B) {
	curve := elliptic.P256()
	publicKey, shares, _ := dealer.NewDealerShares(curve, 2, 3, nil)
	
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3, 4, 5},
	}
	
	paillierKey, _ := generateTestPaillierKey()
	oldData := &dealer.ParticipantData{
		Id:             1,
		SecretKeyShare: shares[1],
		DecryptKey:     paillierKey,
		EcdsaPublicKey: publicKey,
	}
	
	// Generate a message to verify
	p, _ := NewReshareParticipant(1, oldData, publicKey, params)
	messages, _ := p.ReshareRound1()
	msg := messages[2] // Get message for participant 2
	
	// Create recipient participant
	recipient, _ := NewReshareParticipant(2, nil, publicKey, params)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = recipient.verifyFeldmanShare(msg)
	}
}

// Additional test cases for better coverage

func TestResharing_EdgeCases(t *testing.T) {
	curve := elliptic.P256()
	
	t.Run("MinimalThreshold_2of3", func(t *testing.T) {
		// Test with minimal valid threshold (2-of-3)
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		oldParticipants := make(map[uint32]*dealer.ParticipantData)
		for id, share := range shares {
			paillierKey, err := generateTestPaillierKey()
			require.NoError(t, err)
			
			oldParticipants[id] = &dealer.ParticipantData{
				Id:             id,
				SecretKeyShare: share,
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey,
			}
		}
		
		// Reshare to 3-of-4
		params := &Config{
			OldThreshold: 2,
			NewThreshold: 3,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3, 4},
		}
		
		participants := make(map[uint32]*ReshareParticipant)
		for id, data := range oldParticipants {
			p, err := NewReshareParticipant(id, data, publicKey, params)
			require.NoError(t, err)
			participants[id] = p
		}
		
		// Add new participant
		p, err := NewReshareParticipant(4, nil, publicKey, params)
		require.NoError(t, err)
		participants[4] = p
		
		// Execute resharing
		executeTestResharing(t, participants, params)
		
		// Verify results
		for _, p := range participants {
			result, err := p.GetReshareResult()
			require.NoError(t, err)
			assert.NotNil(t, result)
		}
	})
	
	t.Run("SameThresholdDifferentParticipants", func(t *testing.T) {
		// Test resharing with same threshold but different participants
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		oldParticipants := make(map[uint32]*dealer.ParticipantData)
		for id, share := range shares {
			paillierKey, err := generateTestPaillierKey()
			require.NoError(t, err)
			
			oldParticipants[id] = &dealer.ParticipantData{
				Id:             id,
				SecretKeyShare: share,
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey,
			}
		}
		
		// Replace participant 3 with participant 4
		params := &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 4}, // Replace 3 with 4
		}
		
		participants := make(map[uint32]*ReshareParticipant)
		
		// All old participants
		for id, data := range oldParticipants {
			p, err := NewReshareParticipant(id, data, publicKey, params)
			require.NoError(t, err)
			participants[id] = p
		}
		
		// New participant 4
		p, err := NewReshareParticipant(4, nil, publicKey, params)
		require.NoError(t, err)
		participants[4] = p
		
		// Execute resharing
		executeTestResharing(t, participants, params)
		
		// Verify only new participants have results
		for _, id := range params.NewParties {
			result, err := participants[id].GetReshareResult()
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, publicKey.X, result.EcdsaPublicKey.X)
			assert.Equal(t, publicKey.Y, result.EcdsaPublicKey.Y)
		}
	})
	
	t.Run("LargeScaleResharing", func(t *testing.T) {
		// Test with larger number of participants (5-of-9 to 7-of-11)
		publicKey, shares, err := dealer.NewDealerShares(curve, 5, 9, nil)
		require.NoError(t, err)
		
		oldParticipants := make(map[uint32]*dealer.ParticipantData)
		for id, share := range shares {
			paillierKey, err := generateTestPaillierKey()
			require.NoError(t, err)
			
			oldParticipants[id] = &dealer.ParticipantData{
				Id:             id,
				SecretKeyShare: share,
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey,
			}
		}
		
		// Expand to 11 participants with higher threshold
		params := &Config{
			OldThreshold: 5,
			NewThreshold: 7,
			OldParties:   []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9},
			NewParties:   []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		}
		
		participants := make(map[uint32]*ReshareParticipant)
		
		// Old participants
		for id, data := range oldParticipants {
			p, err := NewReshareParticipant(id, data, publicKey, params)
			require.NoError(t, err)
			participants[id] = p
		}
		
		// New participants
		for _, id := range []uint32{10, 11} {
			p, err := NewReshareParticipant(id, nil, publicKey, params)
			require.NoError(t, err)
			participants[id] = p
		}
		
		// Execute resharing
		executeTestResharing(t, participants, params)
		
		// Verify results
		newParticipantData := make(map[uint32]*dealer.ParticipantData)
		for id, p := range participants {
			result, err := p.GetReshareResult()
			require.NoError(t, err)
			newParticipantData[id] = result
		}
		
		err = VerifyReshareResult(newParticipantData, publicKey)
		require.NoError(t, err)
		assert.Len(t, newParticipantData, 11)
	})
}

func TestResharing_ErrorCases(t *testing.T) {
	curve := elliptic.P256()
	publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	require.NoError(t, err)
	
	params := &Config{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []uint32{1, 2, 3},
		NewParties:   []uint32{1, 2, 3},
	}
	
	t.Run("IncompleteRound1Messages", func(t *testing.T) {
		// Test accepting incomplete round 1 messages
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p1, err := NewReshareParticipant(1, oldData, publicKey, params)
		require.NoError(t, err)
		
		p2, err := NewReshareParticipant(2, nil, publicKey, params)
		require.NoError(t, err)
		
		// Generate messages from only one participant (should need all)
		messages1, err := p1.ReshareRound1()
		require.NoError(t, err)
		
		// Try to accept with insufficient messages
		err = p2.ReshareRound1Accept([]*ReshareRound1Bcast{messages1[2]})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "need shares from ALL old participants")
	})
	
	t.Run("WrongRecipientID", func(t *testing.T) {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p1, err := NewReshareParticipant(1, oldData, publicKey, params)
		require.NoError(t, err)
		
		messages, err := p1.ReshareRound1()
		require.NoError(t, err)
		
		// Create participant 2
		p2, err := NewReshareParticipant(2, nil, publicKey, params)
		require.NoError(t, err)
		
		// Try to accept messages from all but with wrong recipient ID
		allMessages := []*ReshareRound1Bcast{}
		for _, id := range params.OldParties {
			// Use message meant for participant 3 instead of 2
			msg := messages[3]
			msg.FromID = id // Fix FromID to make it look like it's from different participants
			allMessages = append(allMessages, msg)
		}
		
		err = p2.ReshareRound1Accept(allMessages)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrong participant")
	})
	
	t.Run("MissingPaillierKeys", func(t *testing.T) {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, params)
		require.NoError(t, err)
		
		// Execute round 1 first
		_, err = p.ReshareRound1()
		require.NoError(t, err)
		
		// Try to accept round 2 with missing Paillier keys
		err = p.ReshareRound2Accept([]*ReshareRound2Bcast{
			{ParticipantID: 2, PublicKey: nil},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Paillier key")
	})
	
	t.Run("MissingPublicShares", func(t *testing.T) {
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, params)
		require.NoError(t, err)
		
		// Advance to round 3
		p.Round = 3
		p.NewShare = &dealer.Share{} // Set dummy share
		
		// Try to accept round 3 with nil public share
		err = p.ReshareRound3Accept([]*ReshareRound3Bcast{
			{ParticipantID: 2, PublicShare: nil},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil public share")
	})
}

func TestResharing_LagrangeCoefficient(t *testing.T) {
	modulus := new(big.Int)
	modulus.SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10) // P-256 order
	
	t.Run("BasicLagrangeCalculation", func(t *testing.T) {
		// Test Lagrange coefficient calculation for simple case
		partyIDs := []uint32{1, 2, 3}
		coeff := calculateLagrangeCoefficient(1, partyIDs, modulus)
		
		// Verify it's not nil and within range
		assert.NotNil(t, coeff)
		assert.Equal(t, coeff.Cmp(modulus), -1) // Should be less than modulus
	})
	
	t.Run("SingleParty", func(t *testing.T) {
		// Edge case: single party should return 1
		partyIDs := []uint32{5}
		coeff := calculateLagrangeCoefficient(5, partyIDs, modulus)
		
		assert.Equal(t, big.NewInt(1), coeff)
	})
}

func TestResharing_AdditionalCoverage(t *testing.T) {
	curve := elliptic.P256()
	
	t.Run("GetReshareResult_NotComplete", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Try to get result before completion
		_, err = p.GetReshareResult()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not complete")
	})
	
	t.Run("GetReshareResult_NoNewShare", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Manually set round to 4 but no new share
		p.Round = 4
		p.NewShare = nil
		
		_, err = p.GetReshareResult()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no new share")
	})
	
	t.Run("Round1_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		_, err := p.ReshareRound1()
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round1Accept_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		err := p.ReshareRound1Accept([]*ReshareRound1Bcast{})
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round2_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		_, err := p.ReshareRound2()
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round2Accept_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		err := p.ReshareRound2Accept([]*ReshareRound2Bcast{})
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round2Accept_InvalidRound", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Wrong round
		err = p.ReshareRound2Accept([]*ReshareRound2Bcast{})
		assert.Error(t, err)
		assert.Equal(t, internal.ErrInvalidRound, err)
	})
	
	t.Run("Round3_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		_, err := p.ReshareRound3()
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round3_InvalidRound", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		p.NewShare = &dealer.Share{} // Set dummy share
		// Wrong round (still 1)
		_, err = p.ReshareRound3()
		assert.Error(t, err)
		assert.Equal(t, internal.ErrInvalidRound, err)
	})
	
	t.Run("Round3_NilSharePoint", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		p.Round = 3
		p.NewShare = &dealer.Share{Point: nil} // Nil point
		
		_, err = p.ReshareRound3()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public share point not computed")
	})
	
	t.Run("Round3Accept_NilArguments", func(t *testing.T) {
		var p *ReshareParticipant
		err := p.ReshareRound3Accept([]*ReshareRound3Bcast{})
		assert.Error(t, err)
		assert.Equal(t, internal.ErrNilArguments, err)
	})
	
	t.Run("Round3Accept_InvalidRound", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Wrong round
		err = p.ReshareRound3Accept([]*ReshareRound3Bcast{})
		assert.Error(t, err)
		assert.Equal(t, internal.ErrInvalidRound, err)
	})
	
	t.Run("Round3Accept_IncompleteShares", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		p.Round = 3
		
		// Create a valid new share with point
		sharePoint, err := curves.NewScalarBaseMult(curve, big.NewInt(123))
		require.NoError(t, err)
		p.NewShare = &dealer.Share{Point: sharePoint}
		
		// Accept incomplete shares (only 1 out of 3 needed)
		err = p.ReshareRound3Accept([]*ReshareRound3Bcast{
			{ParticipantID: 2, PublicShare: &dealer.PublicShare{Point: sharePoint}},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing public shares")
	})
	
	t.Run("Round2Accept_MissingParticipant", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		oldData := &dealer.ParticipantData{
			Id:             1,
			SecretKeyShare: shares[1],
			DecryptKey:     paillierKey,
			EcdsaPublicKey: publicKey,
		}
		
		p, err := NewReshareParticipant(1, oldData, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3, 4}, // Note: 4 participants expected
		})
		require.NoError(t, err)
		
		// Advance to round 2
		p.Round = 2
		
		// Accept messages from only participants 2 and 3 (missing 4)
		err = p.ReshareRound2Accept([]*ReshareRound2Bcast{
			{ParticipantID: 2, PublicKey: &paillierKey.PublicKey},
			{ParticipantID: 3, PublicKey: &paillierKey.PublicKey},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing Paillier key from participant 4")
	})
	
	t.Run("Round1Accept_InvalidShare", func(t *testing.T) {
		publicKey, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		p, err := NewReshareParticipant(2, nil, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Create invalid message with mismatched commitments
		badCommitment, err := curves.NewScalarBaseMult(curve, big.NewInt(999))
		require.NoError(t, err)
		
		invalidMessages := []*ReshareRound1Bcast{
			{
				FromID:      1,
				ToID:        2,
				Share:       big.NewInt(123),
				Commitments: []*curves.EcPoint{badCommitment, badCommitment},
			},
			{
				FromID:      2,
				ToID:        2,
				Share:       big.NewInt(456),
				Commitments: []*curves.EcPoint{badCommitment, badCommitment},
			},
			{
				FromID:      3,
				ToID:        2,
				Share:       big.NewInt(789),
				Commitments: []*curves.EcPoint{badCommitment, badCommitment},
			},
		}
		
		err = p.ReshareRound1Accept(invalidMessages)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid share from participant")
	})
	
	t.Run("VerifyFeldmanShare_ErrorInScalarMult", func(t *testing.T) {
		publicKey, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		p, err := NewReshareParticipant(2, nil, publicKey, &Config{
			OldThreshold: 2,
			NewThreshold: 2,
			OldParties:   []uint32{1, 2, 3},
			NewParties:   []uint32{1, 2, 3},
		})
		require.NoError(t, err)
		
		// Create message with nil commitment to trigger error
		msg := &ReshareRound1Bcast{
			FromID:      1,
			ToID:        2,
			Share:       big.NewInt(123),
			Commitments: []*curves.EcPoint{nil, nil}, // nil will cause error
		}
		
		result := p.verifyFeldmanShare(msg)
		assert.False(t, result)
	})
	
	t.Run("Round1Accept_OldParticipantAsNewParticipant", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		// Create old participants
		oldParticipants := make([]*ReshareParticipant, 0, 3)
		for id, share := range shares {
			oldData := &dealer.ParticipantData{
				Id:             id,
				SecretKeyShare: share,
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey,
			}
			
			p, err := NewReshareParticipant(id, oldData, publicKey, &Config{
				OldThreshold: 2,
				NewThreshold: 2,
				OldParties:   []uint32{1, 2, 3},
				NewParties:   []uint32{1, 2, 3},
			})
			require.NoError(t, err)
			oldParticipants = append(oldParticipants, p)
		}
		
		// Generate shares from all old participants
		allMessages := make(map[uint32][]*ReshareRound1Bcast)
		for _, p := range oldParticipants {
			messages, err := p.ReshareRound1()
			require.NoError(t, err)
			for recipientID, msg := range messages {
				allMessages[recipientID] = append(allMessages[recipientID], msg)
			}
		}
		
		// Old participant 1 (already in round 2) accepts shares as new participant
		err = oldParticipants[0].ReshareRound1Accept(allMessages[1])
		require.NoError(t, err)
		assert.NotNil(t, oldParticipants[0].NewShare)
	})
}

func TestResharing_VerifyReshareResult(t *testing.T) {
	curve := elliptic.P256()
	
	t.Run("EmptyParticipantData", func(t *testing.T) {
		publicKey, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		err = VerifyReshareResult(map[uint32]*dealer.ParticipantData{}, publicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no participant data")
	})
	
	t.Run("NilPublicKey", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		participantData := map[uint32]*dealer.ParticipantData{
			1: {
				Id:             1,
				SecretKeyShare: shares[1],
				DecryptKey:     paillierKey,
				EcdsaPublicKey: nil, // Nil public key
			},
		}
		
		err = VerifyReshareResult(participantData, publicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil public key")
	})
	
	t.Run("MismatchedPublicKey", func(t *testing.T) {
		publicKey1, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		publicKey2, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		participantData := map[uint32]*dealer.ParticipantData{
			1: {
				Id:             1,
				SecretKeyShare: shares[1],
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey2, // Wrong public key
			},
		}
		
		err = VerifyReshareResult(participantData, publicKey1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect public key")
	})
	
	t.Run("MissingSecretShare", func(t *testing.T) {
		publicKey, _, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		paillierKey, err := generateTestPaillierKey()
		require.NoError(t, err)
		
		participantData := map[uint32]*dealer.ParticipantData{
			1: {
				Id:             1,
				SecretKeyShare: nil, // Missing secret share
				DecryptKey:     paillierKey,
				EcdsaPublicKey: publicKey,
			},
		}
		
		err = VerifyReshareResult(participantData, publicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil secret share")
	})
	
	t.Run("MissingDecryptKey", func(t *testing.T) {
		publicKey, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
		require.NoError(t, err)
		
		participantData := map[uint32]*dealer.ParticipantData{
			1: {
				Id:             1,
				SecretKeyShare: shares[1],
				DecryptKey:     nil, // Missing decrypt key
				EcdsaPublicKey: publicKey,
			},
		}
		
		err = VerifyReshareResult(participantData, publicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Paillier key")
	})
}