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

type CircuitVariable interface {
	Values() []frontend.Variable
	SetValues(vs ...frontend.Variable)
}

type Selectable interface {
	Values() []frontend.Variable
	SetValues(vs ...frontend.Variable)
}

type Composable interface {
	FromBinary(api *CircuitAPI, vs ...frontend.Variable) frontend.Variable
}

type Decomposable interface {
	ToBinary(api *CircuitAPI) []frontend.Variable
}

type List[T CircuitVariable] []T

func (t List[T]) Values() []frontend.Variable {
	var ret []frontend.Variable
	for _, data := range t {
		ret = append(ret, data.Values())
	}
	return ret
}

func (t List[T]) SetValues(vs ...frontend.Variable) {
	for i, v := range vs {
		t[i].SetValues(v)
	}
}

// Bytes32 is an in-circuit representation of the solidity bytes32 type.
type Bytes32 struct {
	Val [2]frontend.Variable
}

var MaxBytes32 = ParseBigBytes(common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))

// toBinaryVars defines the circuit that decomposes the Variables into little endian bits
func (b32 Bytes32) toBinaryVars(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
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
// in the form of {lo, hi} This function is not a circuit g and should only be
// used outside of circuit to initialize constant circuit variables
func ParseBytes32(data []byte) Bytes32 {
	if len(data) > 32 {
		panic(fmt.Errorf("ParseBytes32 called with data of length %d", len(data)))
	}

	bits := decomposeBits(new(big.Int).SetBytes(data), 256)

	lo := recompose(bits[:numBitsPerVar], 1)
	hi := recompose(bits[numBitsPerVar:], 1)

	return Bytes32{[2]frontend.Variable{lo, hi}}
}
