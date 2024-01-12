package mux

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const wIn = 2
const nIn = 16

type MuxCircuit struct {
	In       [wIn][nIn]frontend.Variable `gnark:",public"`
	Selector frontend.Variable           `gnark:",public"`
	Out      [wIn]frontend.Variable
}

func convertToSlice(in [wIn][nIn]frontend.Variable) [][]frontend.Variable {
	out := make([][]frontend.Variable, len(in))
	for i := range in {
		out[i] = in[i][:]
	}
	return out
}

func (c *MuxCircuit) Define(api frontend.API) error {
	out := Multiplex(api, c.Selector, wIn, nIn, convertToSlice(c.In))
	for i := 0; i < len(c.Out); i++ {
		api.AssertIsEqual(out[i], c.Out[i])
	}
	return nil
}

func Test_Mux(t *testing.T) {
	assert := test.NewAssert(t)

	var inputs [wIn][nIn]frontend.Variable

	// inputs 0...15
	for i := 0; i < nIn; i++ {
		inputs[0][i] = i
		inputs[1][i] = 15 - i
	}

	r := rand.Intn(16)
	witness := &MuxCircuit{
		In:       inputs,
		Selector: r,
		Out:      [2]frontend.Variable{r, 15 - r},
	}

	err := test.IsSolved(&MuxCircuit{}, witness, ecc.BN254.ScalarField())

	assert.NoError(err)
}
