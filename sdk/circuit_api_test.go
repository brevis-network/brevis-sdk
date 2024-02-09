package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestCasting(t *testing.T) {
	//assert := test.NewAssert(t)

	uint248Max := new(big.Int)
	uint248Max.Lsh(big.NewInt(1), 248).Sub(uint248Max, big.NewInt(1))
	uint256Max := new(big.Int)
	uint256Max.Lsh(big.NewInt(1), 248).Sub(uint256Max, big.NewInt(1))
	circuit := &TestCastingCircuit{
		A: 1,
		B: Bytes32{Val: [2]Uint248{1, 0}},
		C: ParseBigVariable([]byte{1}),
		D: Bytes32{Val: [2]Uint248{uint248Max, 255}},
		E: ParseBigVariable(uint256Max.Bytes()),
	}
	assignment := &TestCastingCircuit{
		A: 1,
		B: Bytes32{Val: [2]Uint248{1, 0}},
		C: ParseBigVariable([]byte{1}),
		D: Bytes32{Val: [2]Uint248{uint248Max, 255}},
		E: ParseBigVariable(uint256Max.Bytes()),
	}
	//
	//ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, circuit)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("constraints", ccs.GetNbConstraints())

	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		panic(err)
	}

	//assert.CheckCircuit(
	//	circuit,
	//	test.WithValidAssignment(assignment),
	//	//test.WithCurves(ecc.BLS12_377),
	//	//test.WithBackends(backend.PLONK),
	//)
}

type TestCastingCircuit struct {
	A Uint248
	B Bytes32
	C *Uint521
	D Bytes32
	E *Uint521
}

func (c *TestCastingCircuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)

	api.AssertIsEqualBytes32(api.ToBytes32(c.A), c.B)
	api.AssertIsEqualBytes32(api.ToBytes32(c.C), c.B)

	api.AssertIsEqual(api.ToVariable(c.B), c.A)
	api.AssertIsEqual(api.ToVariable(c.C), c.A)

	api.AssertIsEqualBig(api.ToBigVariable(c.A), c.C)
	api.AssertIsEqualBig(api.ToBigVariable(c.B), c.C)

	uint256 := api.ToBigVariable(c.D)
	uint512 := api.AddBig(uint256, uint256)
	fmt.Println("1111")
	api.AssertIsEqualBig(uint512, c.E)

	return nil
}
