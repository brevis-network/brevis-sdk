package rlp

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

const shiftnIn = 5

type ShiftLeftCircuit struct {
	In    [shiftnIn]frontend.Variable `gnark:",public"`
	Shift frontend.Variable           `gnark:",public"`
	Out   [shiftnIn]frontend.Variable
}

func (c *ShiftLeftCircuit) Define(api frontend.API) error {
	outs := ShiftLeft(api, shiftnIn, 2, 20, c.In[:], c.Shift)
	for i := 0; i < shiftnIn; i++ {
		api.AssertIsEqual(outs[i], c.Out[i])
	}
	return nil
}

func Test_ShiftLeft(t *testing.T) {
	assert := test.NewAssert(t)

	shift := 2

	// random hex string 0x1234abcfe1, shift=2, so expected result is 0x34abcfe112
	var hex = "0x1234abcfe1"
	var expectHex = "0xabcfe11234"

	assert.Equal((len(hex)-2)/2, shiftnIn)

	data, err := hexutil.Decode(hex)

	assert.NoError(err)

	var inputs [shiftnIn]frontend.Variable
	for i := 0; i < shiftnIn; i++ {
		inputs[i] = data[i]
	}

	expData, err := hexutil.Decode(expectHex)

	var expArr [shiftnIn]frontend.Variable
	for i := 0; i < shiftnIn; i++ {
		expArr[i] = expData[i]
	}
	witness := &ShiftLeftCircuit{
		In:    inputs,
		Shift: shift,
		Out:   expArr,
	}

	err = test.IsSolved(&ShiftLeftCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ShiftRightCircuit struct {
	In    [shiftnIn]frontend.Variable `gnark:",public"`
	Shift frontend.Variable           `gnark:",public"`
	Out   [shiftnIn]frontend.Variable
}

func (c *ShiftRightCircuit) Define(api frontend.API) error {
	outs := ShiftRight(api, shiftnIn, 3, c.In[:], c.Shift)
	for i := 0; i < shiftnIn; i++ {
		api.AssertIsEqual(outs[i], c.Out[i])
	}
	return nil
}

func Test_ShiftRight(t *testing.T) {
	assert := test.NewAssert(t)

	shift := 2

	// random hex string 0x1234abcfe1, shift=2, so expected result is 0x34abcfe112
	var hex = "0x1234abcfe1"
	var expectHex = "0x00001234ab"

	assert.Equal((len(hex)-2)/2, shiftnIn)

	data, err := hexutil.Decode(hex)

	assert.NoError(err)

	var inputs [shiftnIn]frontend.Variable
	for i := 0; i < shiftnIn; i++ {
		inputs[i] = data[i]
	}

	expData, err := hexutil.Decode(expectHex)

	var expArr [shiftnIn]frontend.Variable
	for i := 0; i < shiftnIn; i++ {
		expArr[i] = expData[i]
	}
	witness := &ShiftRightCircuit{
		In:    inputs,
		Shift: shift,
		Out:   expArr,
	}

	err = test.IsSolved(&ShiftRightCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
