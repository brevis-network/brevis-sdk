package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestCasting(t *testing.T) {
	//assert := test.NewAssert(t)

	circuit := &TestCastingCircuit{
		A: 1,
		B: Bytes32{Val: [2]frontend.Variable{1, 0}},
		C: ParseBigVariable([]byte{1}),
	}
	assignment := &TestCastingCircuit{
		A: 1,
		B: Bytes32{Val: [2]frontend.Variable{1, 0}},
		C: ParseBigVariable([]byte{1}),
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
	A Variable
	B Bytes32
	C *BigVariable
}

func (c *TestCastingCircuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)

	api.AssertIsEqualBytes32(api.ToBytes32(c.A), c.B)
	api.AssertIsEqualBytes32(api.ToBytes32(c.C), c.B)

	api.AssertIsEqual(api.ToVariable(c.B), c.A)
	api.AssertIsEqual(api.ToVariable(c.C), c.A)

	api.AssertIsEqualBig(api.ToBigVariable(c.A), c.C)
	api.AssertIsEqualBig(api.ToBigVariable(c.B), c.C)

	return nil
}
