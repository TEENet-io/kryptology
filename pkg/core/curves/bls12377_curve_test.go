//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/stretchr/testify/require"
)

func TestScalarBls12377G1Random(t *testing.T) {
	bls12377g1 := BLS12377G1()
	sc := bls12377g1.Scalar.Random(testRng())
	s, ok := sc.(*ScalarBls12377)
	require.True(t, ok)
	expected, _ := new(big.Int).SetString("022a7db6fad5d5ff49108230818187de316bd0b3e5e96f190397bbb9f28e7a8b", 16)
	require.Equal(t, s.value, expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377g1.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarBls12377)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarBls12377G1Hash(t *testing.T) {
	var b [32]byte
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarBls12377)
	require.True(t, ok)
	expected, _ := new(big.Int).SetString("0c043edae82bf279180b9353139711c1fda5fa64a1f085b80760edaee8f0baca", 16)
	require.Equal(t, s.value, expected)
}

func TestScalarBls12377G1Zero(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarBls12377G1One(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarBls12377G1New(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	require.True(t, three.IsOdd())
	four := bls12377G1.Scalar.New(4)
	require.True(t, four.IsEven())
	neg1 := bls12377G1.Scalar.New(-1)
	require.True(t, neg1.IsEven())
	neg2 := bls12377G1.Scalar.New(-2)
	require.True(t, neg2.IsOdd())
}

func TestScalarBls12377G1Square(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	nine := bls12377G1.Scalar.New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarBls12377G1Cube(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	twentySeven := bls12377G1.Scalar.New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarBls12377G1Double(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	six := bls12377G1.Scalar.New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarBls12377G1Neg(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Scalar.One()
	neg1 := bls12377G1.Scalar.New(-1)
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := bls12377G1.Scalar.New(333333)
	expected := bls12377G1.Scalar.New(-333333)
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarBls12377G1Invert(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarBls12377)
	expected, err := bls12377G1.Scalar.SetBigInt(bhex("0a5f38510051b12ffcd5f1f46c1ef000c0095e8d9000000093d0d55555555556"))
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12377G1Sqrt(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual, err := nine.Sqrt()
	require.NoError(t, err)
	sa, _ := actual.(*ScalarBls12377)
	expected, err := bls12377G1.Scalar.SetBigInt(bhex("12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a117ffffffffffe"))
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12377G1Add(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := bls12377G1.Scalar.New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(3))

	upper, err := bls12377G1.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarBls12377G1Sub(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(3))

	expected, err := bls12377G1.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(bls12377G1.Scalar.New(3)), 0)
}

func TestScalarBls12377G1Mul(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(bls12377G1.Scalar.New(54)), 0)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(1))
	upper, err := bls12377G1.Scalar.SetBigInt(n)
	require.NoError(t, err)
	require.Equal(t, upper.Mul(upper).Cmp(bls12377G1.Scalar.New(1)), 0)
}

func TestScalarBls12377G1Div(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(bls12377G1.Scalar.New(1)), 0)
	require.Equal(t, bls12377G1.Scalar.New(54).Div(nine).Cmp(bls12377G1.Scalar.New(6)), 0)
}

func TestScalarBls12377G1Serialize(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 32)
	require.Equal(t, sequence, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := bls12377G1.Scalar.SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = bls12377G1.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 32)
		ret, err = bls12377G1.Scalar.SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarBls12377G1Nil(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Scalar.New(1)
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, one.Div(nil))
	require.Nil(t, bls12377G1.Scalar.Random(nil))
	require.Equal(t, one.Cmp(nil), -2)
	_, err := bls12377G1.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestScalarBls12377Point(t *testing.T) {
	bls12377G1 := BLS12377G1()
	_, ok := bls12377G1.Scalar.Point().(*PointBls12377G1)
	require.True(t, ok)
	bls12377G2 := BLS12377G2()
	_, ok = bls12377G2.Scalar.Point().(*PointBls12377G2)
	require.True(t, ok)
}

func TestPointBls12377G2Random(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Random(testRng())
	s, ok := sc.(*PointBls12377G2)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("1aa7f3db3f7724096ac07637eac7c73bd9d015dcde3456ff8560064055386d65885a39fb5e39fe5c89f96304e845ce40067469a7dfd7b9a68682f6159b4b6ab5df467acfad30e05c11b9da46a3017d15f8aeee90d3e9e1ce994be8d97741817", 16)
	expectedY, _ := new(big.Int).SetString("56e5eed7cefcfecfff6c63a00a29c0690c2cd3c93fc9154d3b8fc780867761f683c301263bf884daa6afa849d882eb015911417a8db98d3537578a12b86b01c5ae9720d263557a5639c97f3d49e674f8a29da411019c3b84f682e232f6550a", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377G2.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12377G2)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12377G2Hash(t *testing.T) {
	var b [32]byte
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Hash(b[:])
	s, ok := sc.(*PointBls12377G2)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("dd66d931d0fb1410f62d670ee5d1a2de85edee94389eec247674c08f30aeb0ba007e8a811cdd21ebbeb04728a1f7b8007d82f99ee8aa7e41448f62a5ac768c2bca5aac147d73ef29deb1fb06cb2d022499d5f40432b1a4555d1b87858d6d72", 16)
	expectedY, _ := new(big.Int).SetString("893358399f71593d13efe996e66a290635cb557d823e4ec6f83656ad7f46574c7a2f896637a58839d94a6a2a205fc300b70c6015da3c2bf03852f771eb77745448e57a8c96e7b741baa0053e1950cb03c21724a690dc8d25a1dfe11be626d4", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
}

func TestPointBls12377G2Identity(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
}

func TestPointBls12377G2Generator(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Generator()
	s, ok := sc.(*PointBls12377G2)
	require.True(t, ok)
	_, _, _, g2Aff := bls12377.Generators()
	require.True(t, s.value.Equal(&g2Aff))
}

func TestPointBls12377G2Set(t *testing.T) {
	bls12377G2 := BLS12377G2()
	iden, err := bls12377G2.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	_, _, _, g2Aff := bls12377.Generators()
	generator := g2Aff.Bytes()
	_, err = bls12377G2.Point.Set(new(big.Int).SetBytes(generator[:96]), new(big.Int).SetBytes(generator[96:]))
	require.NoError(t, err)
}

func TestPointBls12377G2Double(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	gg2 := g.Double()
	require.True(t, gg2.Equal(g.Mul(bls12377G2.Scalar.New(2))))
	i := bls12377G2.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls12377G2Neg(t *testing.T) {
	bls12377G2 := BLS12377G1()
	g := bls12377G2.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(bls12377G2.Point.Generator()))
	require.True(t, bls12377G2.Point.Identity().Neg().Equal(bls12377G2.Point.Identity()))
}

func TestPointBls12377G2Add(t *testing.T) {
	bls12377G2 := BLS12377G2()
	pt := bls12377G2.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(bls12377G2.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12377G2Sub(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	pt := bls12377G2.Point.Generator().Mul(bls12377G2.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12377G2Mul(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	pt := bls12377G2.Point.Generator().Mul(bls12377G2.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12377G2Serialize(t *testing.T) {
	bls12377G2 := BLS12377G2()
	ss := bls12377G2.Scalar.Random(testRng())
	g := bls12377G2.Point.Generator()

	ppt := g.Mul(ss)
	require.Equal(t, ppt.ToAffineCompressed(), []byte{0x81, 0x88, 0xf4, 0x32, 0xec, 0x60, 0x72, 0xd3, 0x76, 0x77, 0x86, 0xcd, 0x44, 0xce, 0x91, 0x5a, 0x3a, 0xb5, 0x13, 0xe2, 0x81, 0x10, 0x41, 0xa1, 0x39, 0x1e, 0xe2, 0x8a, 0x5f, 0x5f, 0xf1, 0x2e, 0x72, 0xab, 0xc5, 0x62, 0x5c, 0x99, 0x56, 0x5d, 0xd4, 0x33, 0x9a, 0x61, 0x63, 0xd4, 0x8e, 0x7c, 0x0, 0xec, 0x46, 0xb, 0xc4, 0x22, 0xd9, 0xe0, 0x74, 0xe6, 0x79, 0x7b, 0x55, 0x8d, 0x8f, 0x9b, 0xf7, 0x59, 0x65, 0x10, 0x97, 0xe3, 0x12, 0x18, 0xd3, 0x76, 0x3, 0x58, 0x87, 0xc7, 0x82, 0x4c, 0x42, 0x80, 0xa2, 0xa, 0x3d, 0x66, 0xfe, 0xb6, 0xed, 0xd9, 0x38, 0x45, 0x5, 0xbe, 0x40, 0x32})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x1, 0x88, 0xf4, 0x32, 0xec, 0x60, 0x72, 0xd3, 0x76, 0x77, 0x86, 0xcd, 0x44, 0xce, 0x91, 0x5a, 0x3a, 0xb5, 0x13, 0xe2, 0x81, 0x10, 0x41, 0xa1, 0x39, 0x1e, 0xe2, 0x8a, 0x5f, 0x5f, 0xf1, 0x2e, 0x72, 0xab, 0xc5, 0x62, 0x5c, 0x99, 0x56, 0x5d, 0xd4, 0x33, 0x9a, 0x61, 0x63, 0xd4, 0x8e, 0x7c, 0x0, 0xec, 0x46, 0xb, 0xc4, 0x22, 0xd9, 0xe0, 0x74, 0xe6, 0x79, 0x7b, 0x55, 0x8d, 0x8f, 0x9b, 0xf7, 0x59, 0x65, 0x10, 0x97, 0xe3, 0x12, 0x18, 0xd3, 0x76, 0x3, 0x58, 0x87, 0xc7, 0x82, 0x4c, 0x42, 0x80, 0xa2, 0xa, 0x3d, 0x66, 0xfe, 0xb6, 0xed, 0xd9, 0x38, 0x45, 0x5, 0xbe, 0x40, 0x32, 0x0, 0xd, 0x69, 0x94, 0x48, 0x5e, 0x3, 0xd4, 0x51, 0x2a, 0xf6, 0xa, 0xf0, 0x4b, 0xd8, 0x42, 0xc4, 0xc3, 0x66, 0xb8, 0x77, 0x15, 0xaf, 0x8b, 0xee, 0x68, 0xc3, 0xfe, 0x16, 0x4d, 0xd0, 0x5b, 0x97, 0xc, 0x16, 0x6c, 0xfe, 0x9e, 0xc, 0xe0, 0xe3, 0x15, 0x33, 0x6c, 0x81, 0xc1, 0x93, 0x1e, 0x1, 0x13, 0xfc, 0x17, 0xf2, 0x9c, 0xe0, 0x61, 0xe4, 0x58, 0x3a, 0xba, 0xed, 0xd9, 0x2f, 0x54, 0xdd, 0xc3, 0x7f, 0xdf, 0xc0, 0x31, 0x89, 0x1f, 0xf3, 0xcf, 0x9c, 0xac, 0x7c, 0xd, 0x91, 0x8a, 0x84, 0xf8, 0xab, 0xcc, 0x77, 0x55, 0xb6, 0x72, 0xf4, 0xb0, 0x13, 0x45, 0xbb, 0x3d, 0x44, 0xfe})

	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12377G2.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 96)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 192)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls12377G2Nil(t *testing.T) {
	bls12377G2 := BLS12377G2()
	one := bls12377G2.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, bls12377G2.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := bls12377G2.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointBls12377G1Random(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Random(testRng())
	s, ok := sc.(*PointBls12377G1)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("1501005cc2b90240319fa87d59dfa106fa07339124f99915833562dafc3eba8adb3a58e2ce5384374b28b63f98162a0", 16)
	expectedY, _ := new(big.Int).SetString("c262e1475b13467d06747aa9bbfe714a02ca665a3af7d2d68d6341d5a58a715710e7e988a52388bdc334089c940135", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377G1.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12377G1)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12377G1Hash(t *testing.T) {
	var b [32]byte
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Hash(b[:])
	s, ok := sc.(*PointBls12377G1)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("11edd9e3e688cfb761555595eaf4b81b875bedc121cf7d2fb12711c2cd1ce1f4da977c69d195b7a200aa068a17e9b9e", 16)
	expectedY, _ := new(big.Int).SetString("74426f4bb6b1e6caf6d6f2de856e6eeafdebeeaeca6b63603ba25d3b236a6700e01f75cc1f837386aefb60e8d3e531", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
}

func TestPointBls12377G1Identity(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointBls12377G1Generator(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Generator()
	s, ok := sc.(*PointBls12377G1)
	require.True(t, ok)
	_, _, g1Aff, _ := bls12377.Generators()
	require.True(t, s.value.Equal(&g1Aff))
}

func TestPointBls12377G1Set(t *testing.T) {
	bls12377G1 := BLS12377G1()
	iden, err := bls12377G1.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	_, _, g1Aff, _ := bls12377.Generators()
	generator := g1Aff.Bytes()
	_, err = bls12377G1.Point.Set(new(big.Int).SetBytes(generator[:48]), new(big.Int).SetBytes(generator[48:]))
	require.NoError(t, err)
}

func TestPointBls12377G1Double(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(bls12377G1.Scalar.New(2))))
	i := bls12377G1.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls12377G1Neg(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(bls12377G1.Point.Generator()))
	require.True(t, bls12377G1.Point.Identity().Neg().Equal(bls12377G1.Point.Identity()))
}

func TestPointBls12377G1Add(t *testing.T) {
	bls12377G1 := BLS12377G1()
	pt := bls12377G1.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(bls12377G1.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12377G1Sub(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	pt := bls12377G1.Point.Generator().Mul(bls12377G1.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12377G1Mul(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	pt := bls12377G1.Point.Generator().Mul(bls12377G1.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12377G1Serialize(t *testing.T) {
	bls12377G1 := BLS12377G1()
	ss := bls12377G1.Scalar.Random(testRng())
	g := bls12377G1.Point.Generator()

	ppt := g.Mul(ss)
	require.Equal(t, ppt.ToAffineCompressed(), []byte{0xa0, 0xd0, 0xae, 0xea, 0xaa, 0xf1, 0xf6, 0x0, 0x59, 0x39, 0x33, 0x3c, 0x60, 0x16, 0xaf, 0x68, 0x86, 0x2d, 0x3a, 0xc1, 0x73, 0x24, 0xdd, 0x2, 0xb6, 0x49, 0xde, 0xf, 0xe7, 0x42, 0xe8, 0x10, 0xf, 0xab, 0xd1, 0x63, 0xed, 0x13, 0xda, 0x0, 0x69, 0x1b, 0x20, 0x7d, 0xcd, 0x71, 0x7, 0xef})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x0, 0xd0, 0xae, 0xea, 0xaa, 0xf1, 0xf6, 0x0, 0x59, 0x39, 0x33, 0x3c, 0x60, 0x16, 0xaf, 0x68, 0x86, 0x2d, 0x3a, 0xc1, 0x73, 0x24, 0xdd, 0x2, 0xb6, 0x49, 0xde, 0xf, 0xe7, 0x42, 0xe8, 0x10, 0xf, 0xab, 0xd1, 0x63, 0xed, 0x13, 0xda, 0x0, 0x69, 0x1b, 0x20, 0x7d, 0xcd, 0x71, 0x7, 0xef, 0x1, 0x78, 0x3f, 0xbd, 0xd4, 0xbd, 0x7c, 0xf5, 0x7a, 0xfd, 0x33, 0x45, 0x7, 0x39, 0xf2, 0xb7, 0x10, 0x4c, 0x1e, 0xc5, 0x2b, 0x93, 0x4, 0x67, 0x54, 0x88, 0x8b, 0x57, 0x69, 0xf, 0x74, 0x40, 0xf4, 0x58, 0x5b, 0xd7, 0x76, 0x63, 0x58, 0xd9, 0x7b, 0x6d, 0x46, 0x8e, 0x50, 0x89, 0xc4, 0x7d})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12377G1.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 48)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 96)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls12377G1Nil(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, bls12377G1.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := bls12377G1.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointBls12377G1SumOfProducts(t *testing.T) {
	lhs := new(PointBls12377G1).Generator().Mul(new(ScalarBls12377).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointBls12377G1).Generator()
	}
	scalars := []Scalar{
		new(ScalarBls12377).New(8),
		new(ScalarBls12377).New(9),
		new(ScalarBls12377).New(10),
		new(ScalarBls12377).New(11),
		new(ScalarBls12377).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}
