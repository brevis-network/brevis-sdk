package merkle

import (
	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"

	"github.com/consensys/gnark/frontend"
)

type hash = [256]frontend.Variable

// KeccakMerkleRoot computes the root hash of the merkle trie of "leaves"
// leaves must have a length that is power of two
// leaves should already be hashed (keccak) outside this portion of the circuit
func KeccakMerkleRoot(api frontend.API, leaves [][256]frontend.Variable) [256]frontend.Variable {
	leafCount := len(leaves)
	if !isPowerOfTwo(leafCount) {
		panic("leaf count is not power of two")
	}
	return keccakMerkleRoot(api, leaves)
}

func keccakMerkleRoot(api frontend.API, leaves []hash) hash {
	hashes := []hash{}
	if len(leaves) == 1 {
		return leaves[0]
	}
	for i := 0; i < len(leaves); i += 2 {
		data := []frontend.Variable{}
		data = append(data, leaves[i][:]...)
		data = append(data, leaves[i+1][:]...)
		// since the input to the keccak part is always 64 bytes, we can hardwire the padding of 576
		// bits to make it a full round of 1088 bits
		data = pad(data)
		h := keccak.Keccak256Bits(api, 1, 0, data)
		hashes = append(hashes, h)
	}
	return keccakMerkleRoot(api, hashes)
}

func pad(data []frontend.Variable) []frontend.Variable {
	data = append(data, 1)
	for i := 0; i < 574; i++ {
		data = append(data, 0)
	}
	return append(data, 1)
}

func isPowerOfTwo(a int) bool {
	return (a != 0) && ((a & (a - 1)) == 0)
}
