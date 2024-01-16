package emulated

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/gadgets/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"testing"
)

type TestFromElementCircuit[T emulated.FieldParams] struct {
	In         *emulated.Element[T]
	Out        []frontend.Variable
	OutBitSize int
}

func (c *TestFromElementCircuit[T]) Define(api frontend.API) error {
	out := FromElement[T](api, c.In, c.OutBitSize)
	for i := range out {
		api.AssertIsEqual(out[i], c.Out[i])
	}
	return nil
}

func Test_FromElement(t *testing.T) {
	assert := test.NewAssert(t)
	data, _ := hexutil.Decode("0x0000000000000004000000000000000300000000000000020000000000000001")
	el := emulated.ValueOf[emulated.BLS12377Fr](data)
	out := utils.Slice2FVs(data)
	circuit := &TestFromElementCircuit[emulated.BLS12377Fr]{
		In:         &el,
		Out:        out,
		OutBitSize: 8,
	}
	assignment := &TestFromElementCircuit[emulated.BLS12377Fr]{
		In:         &el,
		Out:        out,
		OutBitSize: 8,
	}
	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type TestToElementsCircuit[T emulated.FieldParams] struct {
	In        []frontend.Variable
	Out       []emulated.Element[T]
	InBitSize int
}

func (c *TestToElementsCircuit[T]) Define(api frontend.API) error {
	out := ToElements[T](api, c.In, c.InBitSize)
	for i := range out {
		for j := range out[i].Limbs {
			api.AssertIsEqual(out[i].Limbs[j], c.Out[i].Limbs[j])
		}
	}
	return nil
}

func Test_ToElements(t *testing.T) {
	assert := test.NewAssert(t)
	data0, _ := hexutil.Decode("0x0000000000000004000000000000000300000000000000020000000000000001")
	data1, _ := hexutil.Decode("0x0000000000000004000000000000000300000000000000020000000000000001")
	el0 := emulated.ValueOf[emulated.BLS12377Fr](data0)
	el1 := emulated.ValueOf[emulated.BLS12377Fr](data1)
	in := utils.Slice2FVs(data0)
	in = append(in, utils.Slice2FVs(data1)...)
	out := []emulated.Element[emulated.BLS12377Fr]{el0, el1}
	circuit := &TestToElementsCircuit[emulated.BLS12377Fr]{
		In:        in,
		Out:       out,
		InBitSize: 8,
	}
	assignment := &TestToElementsCircuit[emulated.BLS12377Fr]{
		In:        in,
		Out:       out,
		InBitSize: 8,
	}
	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Printf("constraints %d\n", ccs.GetNbConstraints())
}
