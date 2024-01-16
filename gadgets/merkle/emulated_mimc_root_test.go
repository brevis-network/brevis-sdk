package merkle

import (
	"fmt"
	"github.com/cbergoon/merkletree"
	emu "github.com/celer-network/brevis-sdk/gadgets/emulated"
	"github.com/celer-network/brevis-sdk/gadgets/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"testing"
)

type TestMimcRootAPICircuit struct {
	Leaves     [][]frontend.Variable
	OutBytes   [32]frontend.Variable
	InBitSize  int
	OutBitSize int
}

func (c *TestMimcRootAPICircuit) Define(api frontend.API) error {
	a := NewMimcRootAPI[emulated.BLS12377Fr](api, ecc.BLS12_377)

	els := make([]*emulated.Element[emulated.BLS12377Fr], len(leaves))
	for i := range els {
		leaf := emu.ToElements[emulated.BLS12377Fr](a.api, c.Leaves[i], c.InBitSize)
		els[i] = leaf[0]
	}
	root := a.MimcRoot(els)
	outBytes := emu.FromElement[emulated.BLS12377Fr](a.api, root, c.OutBitSize)
	fmt.Printf("actual root %+v\n", root)
	for i, v := range c.OutBytes {
		api.AssertIsEqual(v, outBytes[i])
	}
	return nil
}

type Leaf struct {
	data []byte
}

func (l Leaf) CalculateHash() ([]byte, error) {
	h := mimc.NewMiMC()
	h.Write(l.data)
	return h.Sum(nil), nil
}

func (l Leaf) Equals(other merkletree.Content) (bool, error) {
	o, ok := other.(Leaf)
	if !ok {
		return false, fmt.Errorf("invalid type")
	}
	for i, v := range l.data {
		if o.data[i] != v {
			return false, nil
		}
	}
	return true, nil
}

var leaves = []merkletree.Content{
	Leaf{hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000001")},
	Leaf{hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000002")},
	Leaf{hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000003")},
	Leaf{hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000004")},
}

func TestMimcRootAPI_MimcRoot(t *testing.T) {
	assert := test.NewAssert(t)
	tree, err := merkletree.NewTreeWithHashStrategy(leaves, mimc.NewMiMC)
	assert.NoError(err)
	root := tree.MerkleRoot()
	fmt.Printf("root %x\n", root)

	var leaves2 [][]frontend.Variable
	for i, leaf := range leaves {
		leaves2 = append(leaves2, make([]frontend.Variable, 32))
		h, err := leaf.CalculateHash()
		if err != nil {
			panic(err)
		}
		for j, b := range h {
			leaves2[i][j] = b
		}
		fmt.Printf("leaves2[%d]: %x\n", i, leaves2[i])
	}

	var expectedOutBytes [32]frontend.Variable
	for i, b := range root {
		expectedOutBytes[i] = b
	}

	circuit := &TestMimcRootAPICircuit{
		Leaves:     leaves2,
		OutBytes:   expectedOutBytes,
		InBitSize:  8,
		OutBitSize: 8,
	}
	assignment := &TestMimcRootAPICircuit{
		Leaves:     leaves2,
		OutBytes:   expectedOutBytes,
		InBitSize:  8,
		OutBitSize: 8,
	}

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Println("constraints", ccs.GetNbConstraints())
}

type TestRestoreMimcRootCircuit struct {
	ExpectedRoot []frontend.Variable
	Leaf         []frontend.Variable
	Branch       [][]frontend.Variable
	LeftRight    []frontend.Variable
	BitSize      int
}

func (c *TestRestoreMimcRootCircuit) Define(api frontend.API) error {
	a := NewMimcRootAPI[emulated.BLS12377Fr](api, ecc.BLS12_377)
	leaf := emu.ToElement[emulated.BLS12377Fr](api, c.Leaf, c.BitSize)
	path := make([]*emulated.Element[emulated.BLS12377Fr], len(c.Branch))
	for i := range c.Branch {
		path[i] = emu.ToElement[emulated.BLS12377Fr](a.api, c.Branch[i], c.BitSize)
	}
	root := a.RestoreMimcRoot(leaf, path, c.LeftRight)
	rootVars := emu.FromElement[emulated.BLS12377Fr](api, root, c.BitSize)
	for i := range c.ExpectedRoot {
		api.AssertIsEqual(c.ExpectedRoot[i], rootVars[i])
	}
	return nil
}

func TestMimcRootAPI_RestoreMimcRoot(t *testing.T) {
	assert := test.NewAssert(t)
	tree, err := merkletree.NewTreeWithHashStrategy(leaves, mimc.NewMiMC)
	assert.NoError(err)
	root := tree.MerkleRoot()
	path, leftRight, err := tree.GetMerklePath(leaves[1])
	assert.NoError(err)
	// flip left right bits because in circuit 0 means path node is on the right
	for i, lr := range leftRight {
		leftRight[i] = 1 - lr
	}

	branch := make([][]frontend.Variable, len(path))
	for i, node := range path {
		branch[i] = utils.Slice2FVs(node)
	}
	leaf, err := leaves[1].CalculateHash()
	assert.NoError(err)

	circuit := &TestRestoreMimcRootCircuit{
		ExpectedRoot: utils.Slice2FVs(root),
		Leaf:         utils.Slice2FVs(leaf),
		Branch:       branch,
		LeftRight:    utils.Slice2FVs(leftRight),
		BitSize:      8,
	}
	assignment := &TestRestoreMimcRootCircuit{
		ExpectedRoot: utils.Slice2FVs(root),
		Leaf:         utils.Slice2FVs(leaf),
		Branch:       branch,
		LeftRight:    utils.Slice2FVs(leftRight),
		BitSize:      8,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
