package keccak

import (
	"fmt"
	"log"

	"github.com/celer-network/brevis-sdk/gadgets/mux"
	"github.com/celer-network/brevis-sdk/gadgets/utils"

	"github.com/consensys/gnark/frontend"
)

// Pad101Bits takes the input and applies the keccak 101 padding, then flips endianess per byte to prepare for the keccak function
//
// simplified example:
// if per keccak round is 8 bits
// for input 1110100 (inLen=7), say fixed circuit variables are inLenMin=6, inLenMax=8, and outLen=16 the matrix looks like
//
// i = data bits
// p = pad bits
// d = dummy bits
// |----i----| |p| |------d--------|    sel
// 1 1 1 0 1 0 1 1 0 0 0 0 0 0 0 0 0     0
// |-----i-----| |--------p--------|
// 1 1 1 0 1 0 0 1 0 0 0 0 0 0 0 0 1     1
// |------i------| |------p--------|
// 1 1 1 0 1 0 0 0 1 0 0 0 0 0 0 0 1     0
//
// The correct padding can then be select by using selector inLen-inLenMin, which is 7-6=1. in this case, it's the row at index 1
//
// IRL, the data needs padding is always bytes, it means we can reduce the amount of rows in the mux to # of bytes in the output
// Output is always bits since the subsequent keccak function only takes bits representation
//
// Circuit params: inBits, inLenMin, inLenMax.
// Variables: in, inLen
//
// `inBits` is the number of bits per element in you `in` slice. e.g. if you intend to pass in a slice of nibbles (range [0,15]), then you should
// tell the function that inBits is 4; and everything else is in nibbles. e.g. inLenMin means the mininum amount of nibbles.
func Pad101Bits(
	api frontend.API,
	inBits, inLenMin, inLenMax int,
	in []frontend.Variable, inLen frontend.Variable,
) []frontend.Variable {
	if len(in) != inLenMax {
		log.Fatalf("Invald input length for pad101. Input max length: %d, Input length: %d", inLenMax, len(in))
	}

	outBitsLen := ((inLenMax*inBits+8)/1088 + 1) * 1088
	fmt.Println("pad: output bits length", outBitsLen)

	checkLen("in", len(in), inBits)
	checkLen("inLenMin", inLenMin, inBits)
	checkLen("inLenMax", inLenMax, inBits)
	checkLen("outBitsLen", outBitsLen, 1)

	var bits []frontend.Variable
	for _, e := range in {
		bs := api.ToBinary(e, inBits)
		for i := range bs {
			bits = append(bits, bs[inBits-i-1])
		}
	}

	// construct mux matrix
	var padded [][]frontend.Variable
	rows := (inLenMax-inLenMin)*inBits/8 + 1
	fmt.Println("pad mux rows", rows)
	for i := 0; i < rows; i++ {
		padded = append(padded, make([]frontend.Variable, outBitsLen))

		// insert the input data part
		var j int
		for j = 0; j < inLenMin*inBits+i*8; j++ {
			padded[i][j] = bits[j]
		}

		actualLen := j
		rounds := (actualLen+8)/1088 + 1

		// insert the padding part
		for ; j < actualLen+7; j++ {
			padded[i][j] = 0
		}
		padded[i][j] = 1
		j++
		for ; j < rounds*1088-8; j++ {
			padded[i][j] = 0
		}
		padded[i][j] = 1
		j++

		// populate the rest with dummy zeros
		for ; j < outBitsLen; j++ {
			padded[i][j] = 0
		}
	}
	sel := api.Div(api.Sub(inLen, inLenMin), 8/inBits)
	out := mux.Multiplex(api, sel, outBitsLen, rows, transpose(padded))

	// flip endianess per byte
	return utils.FlipSubSlice(out, 8)
}

func checkLen(name string, length, inBits int) {
	if length%(8/inBits) != 0 {
		panic(fmt.Sprintf("%s invalid len %d", name, length))
	}
}
