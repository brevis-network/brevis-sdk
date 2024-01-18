package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

// MaxInt is the largest safe number in the BLS12377 scalar field.
var MaxInt = new(big.Int).Sub(ecc.BLS12_377.ScalarField(), big.NewInt(1))

// BLS12377 fr is 253 bits or 32 bytes, but it doesn't mean we can use any
// uint253 because max uint253 would still overflow the field. Reducing the bit
// size to 248 would suffice the purpose.
var numBitsPerVar = 248

// Variable is a direct alias of gnark's frontend.Variable
type Variable = frontend.Variable

// Bytes32 is an in-circuit representation of the solidity bytes32 type.
type Bytes32 struct {
	Val [2]Variable
}

// toBinaryVars defines the circuit that decomposes the Variables into little endian bits
func (b32 Bytes32) toBinaryVars(api frontend.API) []Variable {
	var bits []Variable
	bits = append(bits, api.ToBinary(b32.Val[0], numBitsPerVar)...)
	bits = append(bits, api.ToBinary(b32.Val[1], 32*8-numBitsPerVar)...)
	return bits
}

// toBinary decomposes the Variables into little endian bits
func (b32 Bytes32) toBinary() []uint {
	var bits []uint
	bits = append(bits, decomposeBits(var2BigInt(b32.Val[0]), numBitsPerVar)...)
	bits = append(bits, decomposeBits(var2BigInt(b32.Val[1]), 32*8-numBitsPerVar)...)
	return bits
}

func (b32 Bytes32) String() string {
	left := common.LeftPadBytes(var2BigInt(b32.Val[1]).Bytes(), 1)
	right := common.LeftPadBytes(var2BigInt(b32.Val[0]).Bytes(), 31)
	return fmt.Sprintf("%x%x", left, right)
}

// ParseBytes32 initializes a constant Bytes32 circuit variable. Panics if the
// length of the supplied data bytes is larger than 32. It decomposes data (big
// endian) into little endian bits then recomposes the result into two big ints
// in the form of {lo, hi} This function is not a circuit API and should only be
// used outside of circuit to initialize constant circuit variables
func ParseBytes32(data []byte) Bytes32 {
	if len(data) > 32 {
		panic(fmt.Errorf("ParseBytes32 called with data of length %d", len(data)))
	}

	bits := decomposeBits(new(big.Int).SetBytes(data), 256)

	lo := recompose(bits[:numBitsPerVar], 1)
	hi := recompose(bits[numBitsPerVar:], 1)

	return Bytes32{[2]Variable{lo, hi}}
}

// ParseAddress initializes a circuit Variable from an address type. This
// function is not a circuit API and should only be used outside of circuit to
// initialize constant circuit variables
func ParseAddress(addr [20]byte) Variable {
	return new(big.Int).SetBytes(addr[:])
}

// ParseBytes initializes a circuit Variable from a bytes type. Panics if len(b)
// > 31. This function is not a circuit API and should only be used outside of
// circuit to initialize constant circuit variables
func ParseBytes(b []byte) Variable {
	if len(b) > 31 {
		panic(fmt.Errorf("byte slice of size %d cannot fit into one Variable. use ParseBytes32 instead", len(b)))
	}
	return new(big.Int).SetBytes(b)
}

// ParseBool initializes a circuit Variable from a bool type. This function is
// not a circuit API and should only be used outside of circuit to initialize
// constant circuit variables
func ParseBool(b bool) Variable {
	if b {
		return 1
	}
	return 0
}

// ParseEventID initializes a circuit Variable from bytes. Only the first 6 bytes
// of the event id is used to save space. This function is not a circuit API and
// should only be used outside of circuit to initialize constant circuit
// variables
func ParseEventID(b []byte) Variable {
	return new(big.Int).SetBytes(b[:6])
}