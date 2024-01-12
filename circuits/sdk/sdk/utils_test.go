package sdk

import (
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestDecomposeBits(t *testing.T) {
	bits := decomposeBits(big.NewInt(1234), 12)
	expect := []uint{0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0}
	for i := 0; i < 12; i++ {
		if bits[i] != expect[i] {
			t.Fail()
		}
	}
}

func TestRecompose(t *testing.T) {
	bits := []uint{0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0}
	expect := big.NewInt(1234)
	z := recompose(bits, 1)
	require.True(t, z.Cmp(expect) == 0)
}

func TestPackBitsToInt(t *testing.T) {
	bits := []uint{0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0}
	vars := packBitsToInt(bits, 252)
	require.Equal(t, len(vars), 1)
	require.True(t, vars[0].Cmp(big.NewInt(1234)) == 0)
}
