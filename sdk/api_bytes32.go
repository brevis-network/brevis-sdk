package sdk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
)

// Bytes32 is an in-circuit representation of the solidity bytes32 type.
type Bytes32 struct {
	Val [2]frontend.Variable
}

var _ CircuitVariable = Bytes32{}

func (v Bytes32) Values() []frontend.Variable {
	return v.Val[:]
}

func (v Bytes32) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != 2 {
		panic("Bytes32.FromValues takes 2 param")
	}
	v.Val[0] = vs[0]
	v.Val[1] = vs[1]
	return v
}

func (v Bytes32) NumVars() uint32 { return 2 }

var MaxBytes32 = ConstUint521(common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))

// toBinaryVars defines the circuit that decomposes the Variables into little endian bits
func (v Bytes32) toBinaryVars(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(v.Val[0], numBitsPerVar)...)
	bits = append(bits, api.ToBinary(v.Val[1], 32*8-numBitsPerVar)...)
	return bits
}

// toBinary decomposes the Variables into little endian bits
func (v Bytes32) toBinary() []uint {
	var bits []uint
	bits = append(bits, decomposeBits(fromInterface(v.Val[0]), uint(numBitsPerVar))...)
	bits = append(bits, decomposeBits(fromInterface(v.Val[1]), uint(32*8-numBitsPerVar))...)
	return bits
}

func (v Bytes32) String() string {
	left := common.LeftPadBytes(fromInterface(v.Val[1]).Bytes(), 1)
	right := common.LeftPadBytes(fromInterface(v.Val[0]).Bytes(), 31)
	return fmt.Sprintf("%x%x", left, right)
}

// ConstFromBigEndianBytes initializes a constant Bytes32 circuit variable. Panics if the
// length of the supplied data bytes is larger than 32.
func ConstFromBigEndianBytes(data []byte) Bytes32 {
	if len(data) > 32 {
		panic(fmt.Errorf("ConstBytes32 called with data of length %d", len(data)))
	}

	bits := decomposeBits(new(big.Int).SetBytes(data), 256)

	lo := recompose(bits[:numBitsPerVar], 1)
	hi := recompose(bits[numBitsPerVar:], 1)

	return Bytes32{[2]frontend.Variable{lo, hi}}
}

type Bytes32API struct {
	g frontend.API `gnark:"-"`
}

func newBytes32API(api frontend.API) *Bytes32API {
	return &Bytes32API{api}
}

// ToBinary decomposes the input v to a list (size 256) of little-endian binary digits
func (api *Bytes32API) ToBinary(v Bytes32) List[Uint248] {
	var bits []frontend.Variable
	bits = append(bits, api.g.ToBinary(v.Val[0], numBitsPerVar)...)
	bits = append(bits, api.g.ToBinary(v.Val[1], 32*8-numBitsPerVar)...)
	return newU248s(bits...)
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to a Bytes32. Input size can be less than 256 bits, the
// input is padded on the MSB end with 0s.
func (api *Bytes32API) FromBinary(vs ...Uint248) Bytes32 {
	var list List[Uint248] = vs
	values := list.Values()
	for i := len(vs); i < 256; i++ {
		values = append(values, 0)
	}
	res := Bytes32{}
	res.Val[0] = api.g.FromBinary(values[:numBitsPerVar]...)
	res.Val[1] = api.g.FromBinary(values[numBitsPerVar:]...)
	return res
}

func (api *Bytes32API) FromFV(v frontend.Variable) Bytes32 {
	res := Bytes32{}
	values := api.g.ToBinary(v, 256)
	res.Val[0] = api.g.FromBinary(values[:numBitsPerVar]...)
	res.Val[1] = api.g.FromBinary(values[numBitsPerVar:]...)
	return res
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Bytes32API) IsEqual(a, b Bytes32) Uint248 {
	eq := api.g.And(
		api.g.IsZero(api.g.Sub(a.Val[0], b.Val[0])),
		api.g.IsZero(api.g.Sub(a.Val[1], b.Val[1])),
	)
	return newU248(eq)
}

// Select returns a if s == 1, and b if s == 0
func (api *Bytes32API) Select(s Uint248, a, b Bytes32) Bytes32 {
	res := Bytes32{}
	res.Val[0] = api.g.Select(s.Val, a.Val[0], b.Val[0])
	res.Val[1] = api.g.Select(s.Val, a.Val[1], b.Val[1])
	return res
}

// IsZero returns 1 if a == 0, and 0 otherwise
func (api *Bytes32API) IsZero(a Bytes32) Uint248 {
	return newU248(api.g.And(api.g.IsZero(a.Val[0]), api.g.IsZero(a.Val[1])))
}

// AssertIsEqual asserts a == b
func (api *Bytes32API) AssertIsEqual(a, b Bytes32) {
	api.g.AssertIsEqual(a.Val[0], b.Val[0])
	api.g.AssertIsEqual(a.Val[1], b.Val[1])
}

// AssertIsDifferent asserts a != b
func (api *Bytes32API) AssertIsDifferent(a, b Bytes32) {
	eq := api.IsEqual(a, b)
	api.g.AssertIsEqual(eq.Val, 0)
}
