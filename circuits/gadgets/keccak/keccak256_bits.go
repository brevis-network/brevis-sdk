package keccak

import (
	"fmt"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak/keccakf"
	"github.com/celer-network/brevis-sdk/circuits/gadgets/mux"

	"github.com/consensys/gnark/frontend"
)

func Keccak256Bits(api frontend.API, maxRounds int, roundIndex frontend.Variable, data []frontend.Variable) (out [256]frontend.Variable) {
	if len(data) > maxRounds*1088 {
		panic("len(data) > maxRounds * 1088")
	}
	if len(data)%1088 != 0 {
		panic(fmt.Sprintf("invalid data length %d", len(data)))
	}
	var states [][1600]frontend.Variable
	// initial state
	states = append(states, newEmptyState())
	for i := 0; i < maxRounds; i++ {
		r := getRoundBits(data, i)
		s := absorbBits(api, states[i], r)
		states = append(states, s)
	}

	// TODO skip mux if maxRound == 1
	selected := mux.Multiplex(api, roundIndex, 1600, maxRounds, transpose2(states[1:]))
	copy(out[:], selected[:256])
	return
}

func getRoundBits(data []frontend.Variable, round int) [1088]frontend.Variable {
	var ret [1088]frontend.Variable
	for i := range ret {
		ret[i] = data[i+round*1088]
	}
	return ret
}

func newEmptyState() [1600]frontend.Variable {
	s := [1600]frontend.Variable{}
	for i := 0; i < 1600; i++ {
		s[i] = 0
	}
	return s
}

func transpose2(input [][1600]frontend.Variable) [][]frontend.Variable {
	rows := len(input)
	cols := 1600
	var ret = make([][]frontend.Variable, cols)

	for i := 0; i < cols; i++ {
		ret[i] = make([]frontend.Variable, rows)
		for j := 0; j < rows; j++ {
			ret[i][j] = input[j][i]
		}
	}
	return ret
}

func absorbBits(api frontend.API, s [1600]frontend.Variable, block [1088]frontend.Variable) [1600]frontend.Variable {
	var r [1088]frontend.Variable
	copy(r[:], s[:1088])
	var xored [1600]frontend.Variable
	copy(xored[1088:], s[1088:])
	for i := 0; i < 1088; i++ {
		xored[i] = api.Xor(r[i], block[i])
	}
	return keccakf.Permute(api, xored)
}
