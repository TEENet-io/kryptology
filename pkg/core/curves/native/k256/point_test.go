package k256_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TEENet-io/kryptology/pkg/core/curves/native"
	"github.com/TEENet-io/kryptology/pkg/core/curves/native/k256"
)

func TestK256PointArithmetic_Hash(t *testing.T) {
	var b [32]byte
	sc, err := k256.K256PointNew().Hash(b[:], native.EllipticPointHasherSha256())

	require.NoError(t, err)
	require.True(t, !sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
