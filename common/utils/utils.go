package utils

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
)

func Byte32ToBits(api frontend.API, b32 Bytes32, frSize int) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(b32.Val[0], frSize)...)
	bits = append(bits, api.ToBinary(b32.Val[1], 32*8-frSize)...)
	return bits
}

type Bytes32 struct {
	Val [2]frontend.Variable
}

func Recompose6BytesToNibbles(api frontend.API, d frontend.Variable) [12]frontend.Variable {
	bits := api.ToBinary(d, 48)
	var nibbles [12]frontend.Variable
	for i := 0; i < 12; i++ {
		nibbles[i] = api.FromBinary(bits[i*4 : (i+1)*4]...)
	}
	for i, j := 0, 12-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	return nibbles
}

func Recompose32ByteToNibbles(api frontend.API, trunk []frontend.Variable) [64]frontend.Variable {
	var trunkBits []frontend.Variable

	var truckSize = len(trunk)
	var remainder = 256 % truckSize
	if remainder != 0 {
		panic(fmt.Sprintf("the trunk length %d not allowed", truckSize))
	}
	var trunkPieceBits = 256 / len(trunk)

	for i := 0; i < len(trunk); i++ {
		bs := api.ToBinary(trunk[truckSize-i-1], trunkPieceBits)
		trunkBits = append(trunkBits, bs...)
	}

	var nibbles [64]frontend.Variable
	for i := 0; i < 64; i++ {
		nibbles[i] = api.FromBinary(trunkBits[i*4 : (i+1)*4]...)
	}
	for i, j := 0, 64-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	return nibbles
}

func RecomposeSDKByte32ToNibble(api frontend.API, b32 Bytes32) [64]frontend.Variable {
	h := b32.Val[0]
	l := b32.Val[1]

	var bits []frontend.Variable
	hBits := api.ToBinary(h, 248)
	lBits := api.ToBinary(l, 8)
	bits = append(bits, hBits...)

	bits = append(bits, lBits...)

	var hex [64]frontend.Variable
	for i := 0; i < len(hex); i++ {
		hex[i] = api.FromBinary(bits[i*4 : (i+1)*4]...)
	}

	for i, j := 0, 64-1; i < j; i, j = i+1, j-1 {
		hex[i], hex[j] = hex[j], hex[i]
	}

	return hex
}
