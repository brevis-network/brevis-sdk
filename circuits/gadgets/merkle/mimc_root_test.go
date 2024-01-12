package merkle

import (
	"fmt"
	"testing"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	bls12377MiMC "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type MiMCHashIndexCircuit struct {
	V0    frontend.Variable
	V1    frontend.Variable
	Index frontend.Variable
	Out   frontend.Variable `gnark:",public"`
}

func (c *MiMCHashIndexCircuit) Define(api frontend.API) error {
	miMCHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	out := MiMCHashBasedOnIndex(api, miMCHash, c.V0, c.V1, c.Index)
	api.AssertIsEqual(out, c.Out)
	return nil
}

func TestMiMCHashBasedOnIndex(t *testing.T) {
	assert := test.NewAssert(t)

	miMCHash := bls12377MiMC.NewMiMC()

	left := []byte{0}
	miMCHash.Write(miMCBlockPad0(left, miMCHash.BlockSize()))
	right := []byte{1}
	miMCHash.Write(miMCBlockPad0(right, miMCHash.BlockSize()))

	hash := miMCHash.Sum(nil)
	log.Infof("Hash Result: %s\n", hexutil.Encode(hash))

	var circuit, assignment MiMCHashIndexCircuit

	assignment = MiMCHashIndexCircuit{
		V0:    0,
		V1:    1,
		Index: 0,
		Out:   hash,
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	miMCHash.Reset()
	miMCHash.Write(miMCBlockPad0(right, miMCHash.BlockSize()))
	miMCHash.Write(miMCBlockPad0(left, miMCHash.BlockSize()))
	hash = miMCHash.Sum(nil)

	assignment = MiMCHashIndexCircuit{
		V0:    0,
		V1:    1,
		Index: 1,
		Out:   hash,
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func miMCBlockPad0(data []byte, blockSize int) []byte {
	var block = make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		if i < blockSize-len(data) {
			block[i] = 0
		} else {
			block[i] = data[len(data)-blockSize+i]
		}
	}
	return block
}

type MerkleRootWithMiMCHashCircuit struct {
	Leaf     frontend.Variable
	Indexes  []frontend.Variable
	Branches []frontend.Variable
	Root     frontend.Variable
}

func (c *MerkleRootWithMiMCHashCircuit) Define(api frontend.API) error {
	miMCHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	out := MerkleRootBasedOnMiMCHash(api, miMCHash, c.Leaf, c.Indexes, c.Branches)
	api.AssertIsEqual(out, c.Root)
	fmt.Printf("out %v", out)

	return nil
}

func TestMerkleRootWithMiMCHash(t *testing.T) {
	assert := test.NewAssert(t)

	// miMCHash := bls12377MiMC.NewMiMC()

	leafValue := hexutil.MustDecode("0x078bc78c2211da348075ff95463b41d566a39e66598b366173e132f774a307b2")

	// miMCHash.Reset()
	// miMCHash.Write(leafValue)

	// leafValue = miMCHash.Sum(nil)

	indexInBits := []uint8{1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1}

	branches := make([][]byte, 18)
	bss := []string{
		"0x0134373b65f439c874734ff51ea349327c140cde2e47a933146e6f9f2ad8eb17",
		"0x0a8bca518a0d7c037d0acb441b6e079b2c917faf087dddb5dbfb4f28ddd9234b",
		"0x079088add0fe0111ea10854a338f56a0c95bbef74af24cb880a834136e4e719f",
		"0x1133ca2fa8c93ba25a7399014bfd8d739679abe35c8df04b33c278b8fb33fda4",
		"0x0faab242e28e5796815b7a549ad86aa07f83703309a5d2a999a4726884b09252",
		"0x11d590652648920c5455dce40df2913c792a4a7a9383a0fc4e4467dcf2f72d76",
		"0x00f8f972af22681317766b78a18a5792f92b30443c4cf90b1af5527b24030f90",
		"0x121e0ace6ee2051e585b3e0afdfe768b6879b21477610396bf43e0eeb3319fa6",
		"0x045c0ab3d4fe53b28c732d5782caa83a443c37a0f47f7976f5968b36bd686ceb",
		"0x03f12f0c1032909ce3ab0c972b6698446e2229c5c1007d98bd37242776408ab9",
		"0x0011ee759840c8f6787f4ab3d84d05fa469cdcf8c02570f3ef1dfc5a2c308ecd",
		"0x0d45a15f5ba32214c7f63017a2422a7a6f7ab10ba6cdd84a3146a7d65853b7ed",
		"0x0ccb1ad8c1c9471a7a3291247b3a0f41271a7388da0a99f0f9578b787bce1f2e",
		"0x0c388ea7e0c0251490803e14fa386d008d7273b9defb06c1e16a8872ad133ac9",
		"0x10f776bf618aca530bdef9db0252fdedbcd1f29197fc9cfddd77e19f5e589720",
		"0x084c68d0913e0fafc5aeaa22f0bd713f031814830dfc4b19438bc59c900356bc",
		"0x076d9e8bc28607376ca0f94ade2c78e2500d59c30f4c3438e5e820a937dca6c1",
		"0x0cfc9fdc169f9f27669b4efd379ad01a492759a6348b0792ef844d165b8b9748",
	}
	for i := range indexInBits {
		branches[i] = hexutil.MustDecode(bss[i])
	}
	value := hexutil.MustDecode("0x091d6493780a67da50a508a60f7e85dc10393bddf9207b9c1444ac6f4c13b1dd")

	log.Infof("Hash Result: %s\n", hexutil.Encode(value))

	var circuit, assignment MerkleRootWithMiMCHashCircuit
	indexFV := make([]frontend.Variable, len(indexInBits))

	for i := range indexInBits {
		indexFV[i] = indexInBits[i]
	}

	branchesFV := make([]frontend.Variable, len(indexInBits))

	for i := range indexInBits {
		branchesFV[i] = branches[i]
	}

	assignment = MerkleRootWithMiMCHashCircuit{
		Leaf:     leafValue,
		Indexes:  indexFV,
		Branches: branchesFV,
		Root:     value,
	}

	log.Infof("LeafValue: %v", leafValue)

	circuit = MerkleRootWithMiMCHashCircuit{
		Leaf:     make([]frontend.Variable, len(leafValue)),
		Indexes:  make([]frontend.Variable, len(indexInBits)),
		Branches: make([]frontend.Variable, len(indexInBits)),
		Root:     value,
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BLS12_377.ScalarField())

	assert.NoError(err)
}

func convertByteToBits(bytes []byte) []uint8 {
	var result = make([]uint8, len(bytes)*8)

	for i, b := range bytes {
		result[i*8] = (b & 128) >> 7
		result[i*8+1] = (b & 64) >> 6
		result[i*8+2] = (b & 32) >> 5
		result[i*8+3] = (b & 16) >> 4
		result[i*8+4] = (b & 8) >> 3
		result[i*8+5] = (b & 4) >> 2
		result[i*8+6] = (b & 2) >> 1
		result[i*8+7] = b & 1
	}

	return result
}
