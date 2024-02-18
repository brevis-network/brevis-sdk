package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestUint521(t *testing.T) {
	//assert := test.NewAssert(t)

	uint248Max := new(big.Int)
	uint248Max.Lsh(big.NewInt(1), 248).Sub(uint248Max, big.NewInt(1))
	circuit := &TestUin521Circuit{
		A: newU248(1),
		B: Bytes32{Val: [2]frontend.Variable{1, 0}},
		C: ParseBigBytes([]byte{1}),
	}
	assignment := &TestUin521Circuit{
		A: newU248(1),
		B: Bytes32{Val: [2]frontend.Variable{1, 0}},
		C: ParseBigBytes([]byte{1}),
	}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("constraints", ccs.GetNbConstraints())

	err = test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		panic(err)
	}
}

type TestUin521Circuit struct {
	A Uint248
	B Bytes32
	C Uint521
}

func (c *TestUin521Circuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)
	u521 := NewUint521API(gapi)
	b32 := NewBytes32API(gapi)

	b32.AssertIsEqual(api.ToBytes32(c.A), c.B)
	b32.AssertIsEqual(api.ToBytes32(c.C), c.B)

	api.g.AssertIsEqual(api.ToUint248(c.B), c.A)
	api.g.AssertIsEqual(api.ToUint248(c.C), c.A)

	u521.AssertIsEqual(api.ToUint521(c.A), c.C)
	u521.AssertIsEqual(api.ToUint521(c.B), c.C)

	one := ParseBigBytes([]byte{1})
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ParseBigBytes(_u256Max.Bytes())

	sum := u521.Add(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	u521.AssertIsEqual(sum, ParseBigBytes(_sum.Bytes()))

	diff := u521.Sub(u256Max, u521.Sub(u256Max, one))
	u521.AssertIsEqual(diff, one)

	product := u521.Mul(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	u521.AssertIsEqual(product, ParseBigBytes(_product.Bytes()))

	q, r := u521.Div(ParseBigBytes([]byte{4}), ParseBigBytes([]byte{3}))
	u521.AssertIsEqual(q, one)
	u521.AssertIsEqual(r, ParseBigBytes([]byte{1}))

	q, r = u521.Div(u256Max, u521.Sub(u256Max, one))
	u521.AssertIsEqual(q, one)
	u521.AssertIsEqual(r, one)

	return nil
}
