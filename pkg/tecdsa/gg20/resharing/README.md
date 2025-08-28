# ECDSA GG20 Key Resharing

This package implements threshold ECDSA key resharing for the GG20 protocol. It allows changing the threshold and participant set while preserving the same ECDSA public key.

## Features

- **Threshold Change**: Modify the threshold (t-of-n) without changing participants
- **Participant Addition**: Add new participants to the signing group
- **Participant Removal**: Remove participants while maintaining threshold security
- **Key Preservation**: The ECDSA public key remains unchanged after resharing
- **Feldman VSS**: Uses verifiable secret sharing for secure resharing

## Protocol Overview

The resharing protocol consists of 3 rounds:

1. **Round 1 - Share Generation**: Old participants generate new shares using Feldman VSS
2. **Round 2 - Paillier Key Exchange**: All participants exchange Paillier public keys
3. **Round 3 - Public Share Exchange**: Participants share their public share points

## Usage

```go
import "github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/resharing"

// Define resharing parameters
params := &resharing.ReshareParams{
    OldThreshold: 2,
    NewThreshold: 3,
    OldParties:   []uint32{1, 2, 3},
    NewParties:   []uint32{1, 2, 3, 4, 5},
}

// Create participant
participant, err := resharing.NewReshareParticipant(
    id,
    oldParticipantData, // nil for new participants
    ecdsaPublicKey,
    params,
)

// Execute rounds
messages, err := participant.ReshareRound1()
// ... distribute messages ...
err = participant.ReshareRound1Accept(receivedMessages)

// Continue with rounds 2 and 3...

// Get final result
newParticipantData, err := participant.GetReshareResult()
```

## Common Scenarios

### Adding Participants (3→5)
Change from 3 participants (2-of-3) to 5 participants (3-of-5):
- Old participants: 1, 2, 3
- New participants: 1, 2, 3, 4, 5
- Threshold change: 2 → 3

### Removing Participants (5→3)
Change from 5 participants (3-of-5) to 3 participants (2-of-3):
- Old participants: 1, 2, 3, 4, 5
- New participants: 1, 2, 3
- Threshold change: 3 → 2

### Changing Threshold Only
Increase security by changing threshold from 2-of-5 to 3-of-5:
- Participants: 1, 2, 3, 4, 5 (unchanged)
- Threshold change: 2 → 3

## Security Considerations

- At least `OldThreshold` old participants must participate in resharing
- All new participants must receive shares from sufficient old participants
- The protocol uses Feldman VSS to ensure share validity
- Paillier keys are regenerated during resharing for security

## Testing

Run tests:
```bash
go test ./pkg/tecdsa/gg20/resharing/
```

Run benchmarks:
```bash
go test -bench=. ./pkg/tecdsa/gg20/resharing/
```

## Implementation Notes

This implementation follows the GG20 protocol style used throughout the kryptology library:
- Round-based message passing
- Participant-centric design (no central coordinator)
- Compatible with existing GG20 signing implementation
- Uses the same `dealer.ParticipantData` format for seamless integration