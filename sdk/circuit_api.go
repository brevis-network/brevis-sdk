package sdk

import (
	"fmt"

	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/gnark/frontend"
)

// CircuitAPI contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of gnark's frontend.API.
type CircuitAPI struct {
	frontend.API
	bigField emulated.Field[BigField]

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

// OutputUint adds an output of solidity uint_bitSize type where N is in range [8, 248]
// with a step size 8. e.g. uint8, uint16, ..., uint248.
// Panics if a bitSize of non-multiple of 8 is used.
// Panics if the bitSize exceeds 248. For outputting uint256, use OutputBytes32 instead
func (api *CircuitAPI) OutputUint(bitSize int, i interface{}) {
	if bitSize%8 != 0 {
		panic("bitSize must be multiple of 8")
	}
	switch v := i.(type) {
	case *BigVariable:
		b := api.ToBytes32(v).toBinaryVars(api.API)
		api.addOutput(b)
	case Variable:
		b := api.ToBinary(v, bitSize)
		api.addOutput(b)
	default:
		panic(fmt.Errorf("cannot output variable of type %T, only supports *BigVariable and Variable", i))
	}
	fmt.Printf("added uint%d output: %v\n", bitSize, i)
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

// SolidityMappingStorageKey computes the storage key of a solidity mapping data type.
// https://docs.soliditylang.org/en/v0.8.24/internals/layout_in_storage.html#mappings-and-dynamic-arrays
// keccak256(key | slot)
func (api *CircuitAPI) SolidityMappingStorageKey(mappingKey Bytes32, slot uint) Bytes32 {
	return Bytes32{}
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

func (api *CircuitAPI) ToBytes32(i interface{}) Bytes32 {
	switch v := i.(type) {
	case *BigVariable:
		api.bigField.AssertIsLessOrEqual(v.Element, MaxBytes32.Element)
		return Bytes32{Val: [2]Variable{v.Limbs[0], v.Limbs[1]}}
	case Variable:
		return Bytes32{Val: [2]Variable{v, 0}}
	}
	panic(fmt.Errorf("unsupported casting from %T to Bytes32", i))
}

// ToBigVariable casts a Bytes32 or a Variable type to a BigVariable type
func (api *CircuitAPI) ToBigVariable(i interface{}) *BigVariable {
	switch v := i.(type) {
	case Bytes32:
		el := api.bigField.NewElement(v.Val[:])
		return newBigVariable(el)
	case Variable:
		el := api.bigField.NewElement(v)
		return newBigVariable(el)
	}
	panic(fmt.Errorf("unsupported casting from %T to *BigVariable", i))
}

// ToVariable casts a BigVariable or a Bytes32 type to a Variable type. It
// requires the variable being cast does not overflow the circuit's scalar field
// max
func (api *CircuitAPI) ToVariable(i interface{}) Variable {
	switch v := i.(type) {
	case Bytes32:
		el := api.bigField.NewElement(v.Val[:])
		return newBigVariable(el)
	case *BigVariable:
		reduced := api.bigField.Reduce(v.Element)
		api.AssertIsEqual(reduced.Limbs[1], 0)
		api.AssertIsEqual(reduced.Limbs[2], 0)
		return v.Limbs[0]
	}
	panic(fmt.Errorf("unsupported casting from %T to Variable", i))
}

func (api *CircuitAPI) AddBig(a, b *BigVariable) *BigVariable {
	return newBigVariable(api.bigField.Add(a.Element, b.Element))
}

func (api *CircuitAPI) SubBig(a, b *BigVariable) *BigVariable {
	return newBigVariable(api.bigField.Sub(a.Element, b.Element))
}

func (api *CircuitAPI) MulBig(a, b *BigVariable) *BigVariable {
	return newBigVariable(api.bigField.Mul(a.Element, b.Element))
}

func (api *CircuitAPI) DivBig(a, b *BigVariable) *BigVariable {
	return newBigVariable(api.bigField.Div(a.Element, b.Element))
}
