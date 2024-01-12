package keccak

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestKeccak(t *testing.T) {
	data, _ := hexutil.Decode("0xff00000000000000000000000000000000000000000000000000000000000010ff00000000000000000000000000000000000000000000000000000000000010ff00000000000000000000000000000000000000000000000000000000000010dceb0ddf468b489ddb3ea6a3ef6ec613df11711daeb7d7d390d1148f95054df8dceb0ddf468b489ddb3ea6a3ef6ec613df11711daeb7d7d390d1148f95054df8")
	hash, _ := hexutil.Decode("0x7f55bf028f17dea0c32680c64fd54365e4ded6f3eecec3f31a214e0a5d4025be")

	padded := Pad101(data)
	out := Bytes2Uint64s(hash)
	if len(out) != 4 {
		panic(fmt.Sprintf("out len %d", len(out)))
	}
	w := &Keccak256Circuit{
		RoundIndex: 1,
		Out:        [4]frontend.Variable{out[0], out[1], out[2], out[3]},
	}
	w.Blocks = Uint64s2Blocks(padded)
	for i, el := range out {
		w.Out[i] = el
	}
	circuit := &Keccak256Circuit{}
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type Keccak256Circuit struct {
	Blocks     [MAX_ROUNDS][17]frontend.Variable
	RoundIndex frontend.Variable    `gnark:",public"`
	Out        [4]frontend.Variable `gnark:",public"`
}

func (c *Keccak256Circuit) Define(api frontend.API) error {
	out := Keccak256(api, c.Blocks, c.RoundIndex)
	for i := 0; i < 4; i++ {
		api.AssertIsEqual(out[i], c.Out[i])
	}
	return nil
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
