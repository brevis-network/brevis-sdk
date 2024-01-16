package keccak

import (
	"fmt"
	"testing"

	"github.com/celer-network/brevis-sdk/gadgets/utils"

	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestPad101Bits(t *testing.T) {
	chunk := hexutil.MustDecode("0x1234")
	inLenNibs := 1200
	var data []byte
	for i := 0; i < 300; i++ {
		data = append(data, chunk...)
	}
	var nibs []frontend.Variable
	for _, b := range data {
		nibs = append(nibs, b>>4, b&15)
	}
	for i := len(nibs); i < inLenNibs; i++ {
		nibs = append(nibs, 0)
	}

	padded := utils.Slice2FVs(Bytes2BlockBits(Pad101Bytes(data)))
	c := &PadCircuit{
		DataNibs:   nibs,
		NibsLen:    inLenNibs,
		NibsMin:    0,
		NibsMax:    inLenNibs,
		PaddedBits: padded,
	}
	w := &PadCircuit{
		DataNibs:   nibs,
		NibsLen:    inLenNibs,
		NibsMin:    0,
		NibsMax:    inLenNibs,
		PaddedBits: padded,
	}
	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type PadCircuit struct {
	DataNibs         []frontend.Variable
	NibsLen          frontend.Variable
	NibsMin, NibsMax int

	PaddedBits []frontend.Variable
}

func (c *PadCircuit) Define(api frontend.API) error {
	nibsPadded := Pad101Bits(api, 4, c.NibsMin, c.NibsMax, c.DataNibs, c.NibsLen)
	for i := 0; i < len(c.PaddedBits); i++ {
		api.AssertIsEqual(c.PaddedBits[i], nibsPadded[i])
	}
	return nil
}
