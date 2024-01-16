package keccak

import (
	"github.com/celer-network/brevis-sdk/gadgets/mux"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

const MAX_ROUNDS = 10
const NORMAL_TRANSACTION_LEAF_ROUNDS = 13
const MAX_TRANSACTION_LEAF_ROUNDS = 13

func Keccak256(api frontend.API, blocks [MAX_ROUNDS][17]frontend.Variable, roundIndex frontend.Variable) (out [4]frontend.Variable) {
	var allStates [MAX_ROUNDS + 1][25]frontend.Variable
	var outputStates [][]frontend.Variable
	// initial state
	allStates[0] = [25]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < MAX_ROUNDS; i++ {
		newS := absorb(api, allStates[i], blocks[i])
		allStates[i+1] = newS
		outputStates = append(outputStates, newS[:])
	}
	selected := mux.Multiplex(api, roundIndex, 25, MAX_ROUNDS, transpose(outputStates))
	for i := 0; i < 4; i++ {
		out[i] = selected[i]
	}
	return
}

func Keccak256ForNormalTransaction(api frontend.API, blocks [NORMAL_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable, roundIndex frontend.Variable) (out [4]frontend.Variable) {
	var allStates [NORMAL_TRANSACTION_LEAF_ROUNDS + 1][25]frontend.Variable
	var outputStates [][]frontend.Variable
	// initial state
	allStates[0] = [25]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < NORMAL_TRANSACTION_LEAF_ROUNDS; i++ {
		newS := absorb(api, allStates[i], blocks[i])
		allStates[i+1] = newS
		outputStates = append(outputStates, newS[:])
	}
	selected := mux.Multiplex(api, roundIndex, 25, NORMAL_TRANSACTION_LEAF_ROUNDS, transpose(outputStates))
	for i := 0; i < 4; i++ {
		out[i] = selected[i]
	}
	return
}

func Keccak256ForMaxTransaction(api frontend.API, blocks [MAX_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable, roundIndex frontend.Variable) (out [4]frontend.Variable) {
	var allStates [MAX_TRANSACTION_LEAF_ROUNDS + 1][25]frontend.Variable
	var outputStates [][]frontend.Variable
	// initial state
	allStates[0] = [25]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < MAX_TRANSACTION_LEAF_ROUNDS; i++ {
		newS := absorb(api, allStates[i], blocks[i])
		allStates[i+1] = newS
		outputStates = append(outputStates, newS[:])
	}
	selected := mux.Multiplex(api, roundIndex, 25, MAX_TRANSACTION_LEAF_ROUNDS, transpose(outputStates))
	for i := 0; i < 4; i++ {
		out[i] = selected[i]
	}
	return
}

func transpose(input [][]frontend.Variable) [][]frontend.Variable {
	rows := len(input)
	cols := len(input[0])
	output := make([][]frontend.Variable, cols)

	for i := 0; i < cols; i++ {
		output[i] = make([]frontend.Variable, rows)
		for j := 0; j < rows; j++ {
			output[i][j] = input[j][i]
		}
	}
	return output
}

func absorb(api frontend.API, s [25]frontend.Variable, block [17]frontend.Variable) [25]frontend.Variable {
	// xor block with current state's r bits
	for i := 0; i < 17; i++ {
		rbits := api.ToBinary(s[i], 64)
		blockBits := api.ToBinary(block[i], 64) // TODO maybe pass in blocks as bits so that we save this op
		var xored []frontend.Variable
		for j := 0; j < 64; j++ {
			xored = append(xored, api.Xor(rbits[j], blockBits[j]))
		}
		s[i] = api.FromBinary(xored...)
	}
	return keccakf.PermuteOld(api, s)
}
