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

func TestBigVariable(t *testing.T) {
	//assert := test.NewAssert(t)

	uint248Max := new(big.Int)
	uint248Max.Lsh(big.NewInt(1), 248).Sub(uint248Max, big.NewInt(1))
	circuit := &TestBigVariableCircuit{
		A: 1,
		B: Bytes32{Val: [2]Uint248{1, 0}},
		C: ParseBigVariable([]byte{1}),
		D: Bytes32{Val: [2]Uint248{uint248Max, 255}},
		E: ParseBigVariable(uint256Max.Bytes()),
	}
	assignment := &TestBigVariableCircuit{
		A: 1,
		B: Bytes32{Val: [2]Uint248{1, 0}},
		C: ParseBigVariable([]byte{1}),
		D: Bytes32{Val: [2]Uint248{uint248Max, 255}},
		E: ParseBigVariable(uint256Max.Bytes()),
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

type TestBigVariableCircuit struct {
	A Variable
	B Bytes32
	C *BigVariable
}

func (c *TestBigVariableCircuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)

	api.AssertIsEqualBytes32(api.ToBytes32(c.A), c.B)
	api.AssertIsEqualBytes32(api.ToBytes32(c.C), c.B)

	api.AssertIsEqual(api.ToVariable(c.B), c.A)
	api.AssertIsEqual(api.ToVariable(c.C), c.A)

	api.AssertIsEqualBig(api.ToBigVariable(c.A), c.C)
	api.AssertIsEqualBig(api.ToBigVariable(c.B), c.C)

	one := ParseBigVariable(1)
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ParseBigVariable(_u256Max)

	sum := api.AddBig(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	api.AssertIsEqualBig(sum, ParseBigVariable(_sum))

	diff := api.SubBig(u256Max, api.SubBig(u256Max, one))
	api.AssertIsEqualBig(diff, one)

	product := api.MulBig(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	api.AssertIsEqualBig(product, ParseBigVariable(_product))

	inv := api.DivBig(product, u256Max)
	api.AssertIsEqualBig(inv, u256Max)

	b := api.SubBig(u256Max, one)
	inv = api.DivBig(u256Max, b)
	api.AssertIsEqualBig(api.MulBig(inv, b), u256Max)

	q, r := api.QuoRemBig(ParseBigVariable(4), ParseBigVariable(3))
	api.AssertIsEqualBig(q, one)
	api.AssertIsEqualBig(r, ParseBigVariable(1))

	q, r = api.QuoRemBig(u256Max, b)
	api.AssertIsEqualBig(q, one)
	api.AssertIsEqualBig(r, one)

	return nil
}
