package sdk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// CircuitAPI contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of gnark's frontend.API.
type CircuitAPI struct {
	frontend.API
	output []Variable `gnark:"-"`
}

func NewCircuitAPI(gapi frontend.API) *CircuitAPI {
	api := &CircuitAPI{API: gapi}
	return api
}

// OutputXXX APIs are for processing circuit outputs. The output data is
// committed and submitted on-chain. It can eventually be used in on-chain
// contracts by opening the commitment using
// keccak256(abi.encodedPacked(outputs...))

// OutputBytes32 adds an output of solidity bytes32/uint256 type
func (api *CircuitAPI) OutputBytes32(v Bytes32) {
	b := v.toBinaryVars(api.API)
	api.addOutput(b)
	fmt.Printf("added uint256 output: %s\n", v)
}

// OutputBool adds an output of solidity bool type
func (api *CircuitAPI) OutputBool(v Variable) {
	api.addOutput(api.ToBinary(v, 8))
}

// OutputUint adds an output of solidity uint_bitSize type where N is in range
// [8, 248] with a step size 8. e.g. uint8, uint16, ..., uint248. Panics if a
// bitSize of non-multiple of 8 is used. Panics if the bitSize exceeds 248. For
// outputting uint256, use OutputBytes32 instead
func (api *CircuitAPI) OutputUint(bitSize int, v Variable) {
	if bitSize%8 != 0 {
		panic("bitSize must be multiple of 8")
	}
	if bitSize > 248 {
		panic("bitSIze must be less than or equal to 248")
	}
	b := api.ToBinary(v, bitSize)
	api.addOutput(b)
	fmt.Printf("added uint%d output: %d\n", bitSize, v)
}

// OutputAddress adds an output of solidity address type.
func (api *CircuitAPI) OutputAddress(v Variable) {
	api.addOutput(api.ToBinary(v, 20*8))
	fmt.Printf("added address output: %x\n", v)
}

func (api *CircuitAPI) addOutput(bits []Variable) {
	// the decomposed v bits are little-endian bits. The way evm uses Keccak expects
	// the input to be big-endian bytes, but the bits in each byte are little endian
	b := flipByGroups(bits, 8)
	api.output = append(api.output, b...)
	dryRunOutput = append(dryRunOutput, bits2Bytes(b)...)
}

// ABS returns |a|
func (api *CircuitAPI) ABS(a Variable) Variable {
	return api.Mul(api.Cmp(a, 0), a)
}

// ToVariable casts a Bytes32 type to a Variable type. It requires the variable
// being cast does not exceed the circuit's scalar field max (i.e. around 253
// bits)
func (api *CircuitAPI) ToVariable(b32 Bytes32) Variable {
	api.AssertIsEqual(b32.Val[1], 0)
	return b32.Val[0]
}

// ToBytes32 casts a Variable type to a Bytes32 type.
func (api *CircuitAPI) ToBytes32(v Variable) Bytes32 {
	return Bytes32{[2]Variable{v, 0}}
}

// LT returns 1 if a < b, and 0 otherwise
func (api *CircuitAPI) LT(a, b Variable) Variable {
	return api.IsZero(api.Add(api.Cmp(a, b), 1))
}

// GT returns 1 if a > b, and 0 otherwise
func (api *CircuitAPI) GT(a, b Variable) Variable {
	return api.IsZero(api.Sub(api.Cmp(a, b), 1))
}

// IsBetween returns 1 if a < val < b, 0 otherwise
func (api *CircuitAPI) IsBetween(val, a, b Variable) Variable {
	a = api.Sub(a, 1)
	b = api.Add(b, 1)
	return api.And(api.GT(val, a), api.LT(val, b))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *CircuitAPI) And(a, b Variable, other ...Variable) Variable {
	res := api.API.And(a, b)
	for _, v := range other {
		api.API.And(res, v)
	}
	return res
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *CircuitAPI) Or(a, b Variable, other ...Variable) Variable {
	res := api.API.Or(a, b)
	for _, v := range other {
		api.API.Or(res, v)
	}
	return res
}

// Not returns 1 if `a` is 0, and 0 if `a` is 1. The user must make sure `a` is
// either 0 or 1
func (api *CircuitAPI) Not(a Variable) Variable {
	return api.IsZero(a)
}

// SelectBytes32 returns a if s == 1, and b otherwise
func (api *CircuitAPI) SelectBytes32(s Variable, a, b Bytes32) Bytes32 {
	r := Bytes32{}
	for i := range a.Val {
		r.Val[i] = api.API.Select(s, a.Val[i], b.Val[i])
	}
	return r
}

// AssertIsEqualBytes32 asserts if a == b
func (api *CircuitAPI) AssertIsEqualBytes32(a, b Bytes32) {
	api.AssertIsEqual(api.EqualBytes32(a, b), 1)
}

// EqualBytes32 returns 1 if a == b, and 0 otherwise
func (api *CircuitAPI) EqualBytes32(a, b Bytes32) Variable {
	var result Variable = 1
	for i := range a.Val {
		result = api.API.And(result, api.Equal(a.Val[i], b.Val[i]))
	}
	return result
}

// Equal returns 1 if a == b, and 0 otherwise
func (api *CircuitAPI) Equal(a, b Variable) Variable {
	return api.API.IsZero(api.API.Sub(a, b))
}

// Sqrt returns √a
// Sqrt returns √a. Uses SqrtHint
func (api *CircuitAPI) Sqrt(a Variable) Variable {
	out, err := api.API.Compiler().NewHint(SqrtHint, 1, a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return out[0]
}

// QuoRem computes the standard unsigned integer division a / b and
// its remainder. Uses QuoRemHint.
func (api *CircuitAPI) QuoRem(a, b Variable) (quotient, remainder Variable) {
	out, err := api.API.Compiler().NewHint(QuoRemHint, 2, a, b)
	if err != nil {
		panic(fmt.Errorf("failed to initialize QuoRem hint instance: %s", err.Error()))
	}
	quo, rem := out[0], out[1]
	orig := api.API.Add(api.API.Mul(quo, b), rem)
	api.API.AssertIsEqual(orig, a)
	return quo, rem
}
