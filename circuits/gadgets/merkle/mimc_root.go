package merkle

import (
	"github.com/celer-network/brevis-sdk/circuits/gadgets/rlp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func MerkleRootWithLeaveHash(
	api frontend.API,
	mimcHash mimc.MiMC,
	leafHash frontend.Variable,
	indexes []frontend.Variable,
	branches []frontend.Variable) frontend.Variable {
	api.AssertIsLessOrEqual(len(branches), len(indexes))

	value := leafHash

	for i, branch := range branches {
		value = MiMCHashBasedOnIndex(api, mimcHash, value, branch, indexes[i])
	}

	return value
}

func MerkleRootBasedOnMiMCHash(
	api frontend.API,
	mimcHash mimc.MiMC,
	leaf frontend.Variable,
	indexes []frontend.Variable,
	branches []frontend.Variable) frontend.Variable {
	api.AssertIsLessOrEqual(len(branches), len(indexes))

	mimcHash.Reset()
	mimcHash.Write(leaf)
	value := mimcHash.Sum()
	mimcHash.Reset()

	for i, branch := range branches {
		value = MiMCHashBasedOnIndex(api, mimcHash, value, branch, indexes[i])
	}

	return value
}

func MiMCHashBasedOnIndex(api frontend.API, mimcHash mimc.MiMC, value0, value1, index frontend.Variable) frontend.Variable {
	api.AssertIsLessOrEqual(index, 1)

	mimcHash.Reset()

	mimcHash.Write(value0)
	mimcHash.Write(value1)

	value01 := mimcHash.Sum()

	mimcHash.Reset()
	mimcHash.Write(value1)
	mimcHash.Write(value0)

	value10 := mimcHash.Sum()

	var hashMultiplexerInput [][]frontend.Variable
	hashMultiplexerInput = append(hashMultiplexerInput, make([]frontend.Variable, 2))
	hashMultiplexerInput[0][0] = value01
	hashMultiplexerInput[0][1] = value10
	return rlp.Multiplexer(api, index, 1, 2, hashMultiplexerInput)[0]
}
