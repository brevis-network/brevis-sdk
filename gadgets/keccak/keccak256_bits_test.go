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

func TestKeccakBits(t *testing.T) {
	maxRounds := 2
	// 1 round
	roundIndex := 0
	data, _ := hexutil.Decode("0xff00000000000000000000000000000000000000000000000000000000000010ff")
	hash, _ := hexutil.Decode("0x746cc57064795780b008312042c24f949ad9dc0ee2dce9f4828f5a8869ccecca")

	// 2 rounds
	// roundIndex := 1
	// data, _ := hexutil.Decode("0xff00000000000000000000000000000000000000000000000000000000000010ff00000000000000000000000000000000000000000000000000000000000010ff00000000000000000000000000000000000000000000000000000000000010dceb0ddf468b489ddb3ea6a3ef6ec613df11711daeb7d7d390d1148f95054df8dceb0ddf468b489ddb3ea6a3ef6ec613df11711daeb7d7d390d1148f95054df8")
	// hash, _ := hexutil.Decode("0x7f55bf028f17dea0c32680c64fd54365e4ded6f3eecec3f31a214e0a5d4025be")

	padded := Pad101Bytes(data)
	paddedBits := Bytes2BlockBits(padded)
	out := Bytes2Bits(hash)
	if len(out) != 256 {
		panic(fmt.Sprintf("out len %d", len(out)))
	}
	var out256 [256]frontend.Variable
	for i, v := range out {
		out256[i] = frontend.Variable(v)
	}
	var dataBits []frontend.Variable
	// convert int array to frontend.Variable array
	for _, b := range paddedBits {
		dataBits = append(dataBits, b)
	}
	// fill the rest with 0s
	zerosToPad := maxRounds*1088 - len(dataBits)
	for i := 0; i < zerosToPad; i++ {
		dataBits = append(dataBits, 0)
	}
	w := &Keccak256BitsCircuit{
		MaxRounds:  maxRounds,
		RoundIndex: roundIndex,
		Out:        out256,
		Data:       dataBits,
	}
	circuit := &Keccak256BitsCircuit{
		MaxRounds:  maxRounds,
		RoundIndex: roundIndex,
		Out:        out256,
		Data:       dataBits,
	}
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type Keccak256BitsCircuit struct {
	MaxRounds  int
	Data       []frontend.Variable
	RoundIndex frontend.Variable      `gnark:",public"`
	Out        [256]frontend.Variable `gnark:",public"`
}

func (c *Keccak256BitsCircuit) Define(api frontend.API) error {
	out := Keccak256Bits(api, c.MaxRounds, c.RoundIndex, c.Data)
	for i := 0; i < 256; i++ {
		api.AssertIsEqual(out[i], c.Out[i])
	}
	return nil
}
