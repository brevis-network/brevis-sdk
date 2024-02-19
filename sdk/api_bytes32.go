package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

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
	bits = append(bits, decomposeBits(fromInterface(b32.Val[0]), uint(numBitsPerVar))...)
	bits = append(bits, decomposeBits(fromInterface(b32.Val[1]), uint(32*8-numBitsPerVar))...)
	return bits
}

func (b32 Bytes32) String() string {
	left := common.LeftPadBytes(fromInterface(b32.Val[1]).Bytes(), 1)
	right := common.LeftPadBytes(fromInterface(b32.Val[0]).Bytes(), 31)
	return fmt.Sprintf("%x%x", left, right)
}

// ConstBytes32 initializes a constant Bytes32 circuit variable. Panics if the
// length of the supplied data bytes is larger than 32. It decomposes data (big
// endian) into little endian bits then recomposes the result into two big ints
// in the form of {lo, hi} This function is not a circuit g and should only be
// used outside of circuit to initialize constant circuit variables
func ConstBytes32(data []byte) Bytes32 {
	if len(data) > 32 {
		panic(fmt.Errorf("ConstBytes32 called with data of length %d", len(data)))
	}

	bits := decomposeBits(new(big.Int).SetBytes(data), 256)

	lo := recompose(bits[:numBitsPerVar], 1)
	hi := recompose(bits[numBitsPerVar:], 1)

	return Bytes32{[2]frontend.Variable{lo, hi}}
}

type Bytes32API struct {
	g frontend.API
}

func NewBytes32API(api frontend.API) *Bytes32API {
	return &Bytes32API{api}
}

func (api *Bytes32API) ToBinary(v Bytes32) []Uint248 {
	var bits []frontend.Variable
	bits = append(bits, api.g.ToBinary(v.Val[0], numBitsPerVar)...)
	bits = append(bits, api.g.ToBinary(v.Val[1], 32*8-numBitsPerVar)...)
	return newU248s(bits...)
}

func (api *Bytes32API) IsEqual(a, b Bytes32) Uint248 {
	eq := api.g.And(
		api.g.IsZero(api.g.Sub(a.Val[0], b.Val[0])),
		api.g.IsZero(api.g.Sub(a.Val[1], b.Val[1])),
	)
	return newU248(eq)
}

func (api *Bytes32API) Select(s Uint248, a, b Bytes32) Bytes32 {
	res := Bytes32{}
	res.Val[0] = api.g.Select(s.Val, a.Val[0], b.Val[0])
	res.Val[1] = api.g.Select(s.Val, a.Val[1], b.Val[1])
	return res
}

func (api *Bytes32API) IsZero(a Bytes32) Uint248 {
	return newU248(api.g.And(api.g.IsZero(a.Val[0]), api.g.IsZero(a.Val[1])))
}

func (api *Bytes32API) AssertIsEqual(a, b Bytes32) {
	api.g.AssertIsEqual(a.Val[0], b.Val[0])
	api.g.AssertIsEqual(a.Val[1], b.Val[1])
}

func (api *Bytes32API) AssertIsDifferent(a, b Bytes32) {
	eq := api.IsEqual(a, b)
	api.g.AssertIsEqual(eq.Val, 0)
}
