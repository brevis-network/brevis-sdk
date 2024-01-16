package rlp

import (
	"math/rand"
	"strconv"
	"testing"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const ArrayEqualLength = 28

type EqualCircuit struct {
	A   frontend.Variable `gnark:",public"`
	B   frontend.Variable `gnark:",public"`
	Out frontend.Variable `gnark:",public"`
}

type LessThanCircuit struct {
	A   frontend.Variable `gnark:",public"`
	B   frontend.Variable `gnark:",public"`
	Out frontend.Variable `gnark:",public"`
}

type ArrayEqualCircuit struct {
	A            [ArrayEqualLength]frontend.Variable `gnark:",public"`
	B            [ArrayEqualLength]frontend.Variable `gnark:",public"`
	TargetLength frontend.Variable                   `gnark:",public"`
	Out          frontend.Variable                   `gnark:",public"`
}

func (c *ArrayEqualCircuit) Define(api frontend.API) error {
	out := ArrayEqual(api, c.A[:], c.B[:], ArrayEqualLength, c.TargetLength)
	api.AssertIsEqual(out, c.Out)
	return nil
}

func (c *EqualCircuit) Define(api frontend.API) error {
	out := Equal(api, c.A, c.B)
	api.AssertIsEqual(out, c.Out)
	return nil
}

func (c *LessThanCircuit) Define(api frontend.API) error {
	out := LessThan(api, c.A, c.B)
	api.AssertIsEqual(out, c.Out)
	return nil
}

func Test_Array_Equal(t *testing.T) {
	assert := test.NewAssert(t)

	var A [ArrayEqualLength]frontend.Variable
	var B [ArrayEqualLength]frontend.Variable
	var C [ArrayEqualLength]frontend.Variable

	for i := 0; i < ArrayEqualLength; i++ {
		value := rand.Intn(ArrayEqualLength)
		A[i] = value
		B[i] = value
		C[i] = rand.Intn(ArrayEqualLength) + ArrayEqualLength
	}

	witness := &ArrayEqualCircuit{
		A:            A,
		B:            B,
		TargetLength: ArrayEqualLength,
		Out:          1,
	}

	err := test.IsSolved(&ArrayEqualCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	witness = &ArrayEqualCircuit{
		A:            A,
		B:            C,
		TargetLength: ArrayEqualLength,
		Out:          1,
	}

	err = test.IsSolved(&ArrayEqualCircuit{}, witness, ecc.BN254.ScalarField())
	assert.Error(err, "")
}

func Test_Simple_Comparator(t *testing.T) {
	assert := test.NewAssert(t)
	equal := &EqualCircuit{
		A:   100000,
		B:   100000,
		Out: 1,
	}
	err := test.IsSolved(&EqualCircuit{}, equal, ecc.BN254.ScalarField())
	assert.NoError(err)

	equal = &EqualCircuit{
		A:   100000,
		B:   1231,
		Out: 1,
	}
	err = test.IsSolved(&EqualCircuit{}, equal, ecc.BN254.ScalarField())
	assert.Error(err)

	lessThan := &LessThanCircuit{
		A:   10,
		B:   11,
		Out: 1,
	}
	err = test.IsSolved(&LessThanCircuit{}, lessThan, ecc.BN254.ScalarField())
	assert.NoError(err)

	lessThan = &LessThanCircuit{
		A:   -2,
		B:   -2,
		Out: 1,
	}
	err = test.IsSolved(&LessThanCircuit{}, lessThan, ecc.BN254.ScalarField())
	assert.Error(err)
}

type SubArrayCircuit struct {
	In        [64]frontend.Variable `gnark:",public"`
	From      frontend.Variable
	End       frontend.Variable
	Out       [64]frontend.Variable
	OutLength frontend.Variable
}

func (c *SubArrayCircuit) Define(api frontend.API) error {
	subArray := NewSubArray(64, 64, 7)
	result, outLength := subArray.SubArray(api, c.In[:], c.From, c.End)
	log.Info(result)
	for i := 0; i < shiftnIn; i++ {
		api.AssertIsEqual(result[i], c.Out[i])
	}
	api.AssertIsEqual(c.OutLength, outLength)
	return nil
}

func Test_SubArray(t *testing.T) {
	assert := test.NewAssert(t)

	keyRlpHexString := "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	keyHexLen := len(keyRlpHexString)
	var input [64]frontend.Variable
	var out [64]frontend.Variable

	from := 2
	end := 64

	for i := 0; i < 64; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			input[i] = intValue
		} else {
			input[i] = 0
		}
	}

	m := input[from:end]

	for i := 0; i < 64; i++ {
		if i < len(m) {
			out[i] = m[i]
		} else {
			out[i] = 0
		}
	}

	witness := &SubArrayCircuit{
		input,
		from,
		end,
		out,
		end - from,
	}

	err := test.IsSolved(&SubArrayCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiplexerTest struct {
	Data [][]frontend.Variable
	Sel  frontend.Variable
	Out  []frontend.Variable
}

func (c *MultiplexerTest) Define(api frontend.API) error {
	out := Multiplexer(api, c.Sel, 1, 10, c.Data)
	for i := range c.Out {
		api.AssertIsEqual(out[i], c.Out[i])
	}
	return nil
}

func TestMultiplexer(t *testing.T) {
	var row = 1
	var cols = 10
	var circuit, assignment MultiplexerTest

	data := make([][]frontend.Variable, row)
	for i := range data {
		data[i] = make([]frontend.Variable, cols)
	}

	circuit.Data = data
	circuit.Out = make([]frontend.Variable, 1)

	assignment.Data = make([][]frontend.Variable, row)
	for i := range assignment.Data {
		assignment.Data[i] = []frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	}
	assignment.Out = append(assignment.Out, 2)
	assignment.Sel = 1

	err := test.IsSolved(&circuit, &assignment, ecc.BLS12_377.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}
