package limbs

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestLimbAPI(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &TestCircuit{
		Limbs: Limbs{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	assignment := &TestCircuit{
		Limbs: Limbs{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	fmt.Println("compile")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Println("constraints", cs.GetNbConstraints())

	fmt.Println("setup")
	pk, vk, err := groth16.Setup(cs)
	assert.NoError(err)

	fmt.Println("gen witness")
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	fmt.Println("prove")
	solverOpt := solver.WithHints(SplitHint)
	proof, err := groth16.Prove(cs, pk, w, backend.WithSolverOptions(solverOpt))
	assert.NoError(err)

	fmt.Println("verify")
	err = groth16.Verify(proof, vk, pw)
	assert.NoError(err)
	// assert.ProverSucceeded(
	// 	c, w,
	// 	test.WithSolverOpts(solver.WithHints(SplitHint)),
	// 	test.WithCurves(ecc.BN254),
	// 	test.WithBackends(backend.GROTH16),
	// )
}

type TestCircuit struct {
	Limbs Limbs
}

func (c *TestCircuit) Define(api frontend.API) error {
	wa := NewAPI(api)
	w := c.Limbs[0]
	fmt.Println("test split limbSize 8")
	split := wa.Split(w, 8)
	checkLen(split, 1)
	api.AssertIsEqual(split.TotalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10001001").Val)

	fmt.Println("test split: limbSize 4")
	split = wa.Split(w, 4)
	checkLen(split, 2)
	api.AssertIsEqual(split.TotalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("1000").Val)
	api.AssertIsEqual(split[0].Size, 4)
	api.AssertIsEqual(split[1].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[1].Size, 4)

	fmt.Println("test split: limbSize 2, nb limbs 2")
	split = wa.Split(w, 2, 2)
	checkLen(split, 3)
	api.AssertIsEqual(split.TotalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10").Val)
	api.AssertIsEqual(split[0].Size, 2)
	api.AssertIsEqual(split[1].Val, parseBinary("00").Val)
	api.AssertIsEqual(split[1].Size, 2)
	api.AssertIsEqual(split[2].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[2].Size, 4)

	fmt.Println("test LrotMerge: amount 1")
	rotated := wa.LrotMerge(c.Limbs, 1)
	api.AssertIsEqual(rotated.Size, 24)
	api.AssertIsEqual(rotated.Val, parseBinary("000100101010100110011011").Val)

	fmt.Println("test Lrot: amount 1, limbSize 8")
	rs := wa.Lrot(c.Limbs, 1, 8)
	checkLen(rs, 3)
	api.AssertIsEqual(rs.TotalSize(), 24)
	api.AssertIsEqual(rs[0].Val, parseBinary("00010010").Val)
	api.AssertIsEqual(rs[0].Size, 8)
	api.AssertIsEqual(rs[1].Val, parseBinary("10101001").Val)
	api.AssertIsEqual(rs[1].Size, 8)
	api.AssertIsEqual(rs[2].Val, parseBinary("10011011").Val)
	api.AssertIsEqual(rs[2].Size, 8)

	fmt.Println("test Merge")
	m := wa.Merge(c.Limbs)
	api.AssertIsEqual(m.Size, 24)
	api.AssertIsEqual(m.Val, parseBinary("100010010101010011001101").Val)

	fmt.Println("test Resplit: newLimbSize 12")
	split = wa.Resplit(c.Limbs, 12)
	checkLen(split, 2)
	api.AssertIsEqual(split.TotalSize(), c.Limbs.TotalSize())
	api.AssertIsEqual(split[0].Val, parseBinary("100010010101").Val)
	api.AssertIsEqual(split[1].Val, parseBinary("010011001101").Val)

	fmt.Println("test Resplit: re-split four 64-bit limbs into two 128-bit limbs")
	ws := Limbs{
		parseBinaryBig("1001010101001100100101010100110010010101010011001001010101001100"),
		parseBinaryBig("1001010101001100100101010100110010010101010011001001010101001100"),
		parseBinaryBig("1001010101001100100101010100110010010101010011001001010101001100"),
		parseBinaryBig("1001010101001100100101010100110010010101010011001001010101001100"),
	}
	split = wa.Resplit(ws, 128)
	checkLen(split, 2)
	api.AssertIsEqual(split.TotalSize(), ws.TotalSize())
	api.AssertIsEqual(split[0].Val, parseBinaryBig("10010101010011001001010101001100100101010100110010010101010011001001010101001100100101010100110010010101010011001001010101001100").Val)
	api.AssertIsEqual(split[1].Val, parseBinaryBig("10010101010011001001010101001100100101010100110010010101010011001001010101001100100101010100110010010101010011001001010101001100").Val)
	return nil
}
