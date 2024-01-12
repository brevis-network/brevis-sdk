package merkle

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestKeccakMerkleRoot(t *testing.T) {
	zero := hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000")
	// leaves4 := [][]byte{zero, zero, zero, zero}
	// root4, _ := hexutil.Decode("0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
	leaves8 := [][]byte{zero, zero, zero, zero, zero, zero, zero, zero}
	root8, _ := hexutil.Decode("0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85")
	w := &KeccakMerkleRootCircuit{
		Root:   bytes2Hash(root8),
		Leaves: encode(leaves8),
	}
	circuit := &KeccakMerkleRootCircuit{
		Root:   bytes2Hash(root8),
		Leaves: encode(leaves8),
	}
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type KeccakMerkleRootCircuit struct {
	Root   hash `gnark:",public"`
	Leaves []hash
}

func (c *KeccakMerkleRootCircuit) Define(api frontend.API) error {
	root := KeccakMerkleRoot(api, c.Leaves)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(root[i], c.Root[i])
	}
	return nil
}

func encode(leaves [][]byte) []hash {
	ret := []hash{}
	for _, leaf := range leaves {
		ret = append(ret, bytes2Hash(leaf))
	}
	return ret
}

func bytes2Hash(bytes []byte) hash {
	h := hash{}
	for i, b := range bytes {
		for j := 0; j < 8; j++ {
			h[i*8+j] = (b >> j) & 1
		}
	}
	return h
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
