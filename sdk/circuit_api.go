package sdk

import (
	"fmt"

	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/gnark/frontend"
)

// CircuitAPI contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of g's frontend.API.
type CircuitAPI struct {
	g        frontend.API
	bigField *emulated.Field[BigField]

	output []Variable `g:"-"`
}

func NewCircuitAPI(gapi frontend.API) *CircuitAPI {
	f, err := emulated.NewField[BigField](gapi)
	if err != nil {
		panic(err)
	}
	api := &CircuitAPI{g: gapi, bigField: f}
	return api
}

// OutputXXX APIs are for processing circuit outputs. The output data is
// committed and submitted on-chain. It can eventually be used in on-chain
// contracts by opening the commitment using
// keccak256(abi.encodedPacked(outputs...))

// OutputBytes32 adds an output of solidity bytes32/uint256 type
func (api *CircuitAPI) OutputBytes32(v Bytes32) {
	b := v.toBinaryVars(api.g)
	api.addOutput(b)
	fmt.Printf("added uint256 output: %s\n", v)
}

// OutputBool adds an output of solidity bool type
func (api *CircuitAPI) OutputBool(v Variable) {
	api.addOutput(api.g.ToBinary(v, 8))
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
		b := api.ToBytes32(v).toBinaryVars(api.g)
		api.addOutput(b)
	case Variable:
		b := api.g.ToBinary(v, bitSize)
		api.addOutput(b)
	default:
		panic(fmt.Errorf("cannot output variable of type %T, only supports *BigVariable and Variable", i))
	}
	fmt.Printf("added uint%d output: %v\n", bitSize, i)
}

// OutputAddress adds an output of solidity address type.
func (api *CircuitAPI) OutputAddress(v Variable) {
	api.addOutput(api.g.ToBinary(v, 20*8))
	fmt.Printf("added address output: %x\n", v)
}

func (api *CircuitAPI) addOutput(bits []frontend.Variable) {
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

func Cmp(api *CircuitAPI, a, b Variable) Variable {
	return newVariable(api.g.Cmp(a.Val, b.Val))
}

// LT returns 1 if a < b, and 0 otherwise
func LT(api *CircuitAPI, a, b Variable) Variable {
	return IsZero(api, Add(api, Cmp(api, a, b), newVariable(1)))
}

// GT returns 1 if a > b, and 0 otherwise
func GT(api *CircuitAPI, a, b Variable) Variable {
	return IsZero(api, Sub(api, newVariable(Cmp(api, a, b)), newVariable(1)))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func And(api *CircuitAPI, a, b Variable, other ...Variable) Variable {
	res := api.g.And(a.Val, b.Val)
	for _, v := range other {
		api.g.And(res, v)
	}
	return newVariable(res)
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func Or(api *CircuitAPI, a, b Variable, other ...Variable) Variable {
	res := api.g.Or(a.Val, b.Val)
	for _, v := range other {
		api.g.Or(res, v.Val)
	}
	return newVariable(res)
}

// Not returns 1 if `a` is 0, and 0 if `a` is 1. The user must make sure `a` is
// either 0 or 1
func Not(api *CircuitAPI, a Variable) Variable {
	return IsZero(api, a)
}

func Select[T CircuitVariable](api *CircuitAPI, s Variable, a, b T) T {
	aVals := a.Values()
	bVals := b.Values()
	if len(aVals) != len(bVals) {
		panic(fmt.Errorf("cannot select: inconsistent value length of a (%d) and b (%d)", len(aVals), len(bVals)))
	}
	res := make([]frontend.Variable, len(aVals))
	for i := range aVals {
		res[i] = api.g.Select(s, aVals[i], bVals[i])
	}
	t := *new(T)
	t.SetValues(res)
	return t
}

// Equal returns 1 if a == b, and 0 otherwise
func Equal(api *CircuitAPI, a, b Variable) Variable {
	return IsZero(api, Sub(api, a, b))
}

func Sub(api *CircuitAPI, a, b Variable) Variable {
	return newVariable(api.g.Sub(a.Val, b.Val))
}

func IsZero(api *CircuitAPI, a Variable) Variable {
	return newVariable(api.g.IsZero(a.Val))
}

// Sqrt returns √a. Uses SqrtHint
func (api *CircuitAPI) Sqrt(a Variable) Variable {
	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return out[0]
}

type Var interface {
	Variable | BigVariable
}

// QuoRem computes the standard unsigned integer division a / b and
// its remainder. Uses QuoRemHint.
func (api *CircuitAPI) QuoRem(a, b Variable) (quotient, remainder Variable) {
	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a, b)
	if err != nil {
		panic(fmt.Errorf("failed to initialize QuoRem hint instance: %s", err.Error()))
	}
	quo, rem := out[0], out[1]
	orig := api.g.Add(api.g.Mul(quo, b), rem)
	api.g.AssertIsEqual(orig, a)
	return quo, rem
}

func (api *CircuitAPI) ToBytes32(i interface{}) Bytes32 {
	switch v := i.(type) {
	case *BigVariable:
		api.bigField.AssertIsLessOrEqual(v.Element, MaxBytes32.Element)
		r := api.bigField.Reduce(v.Element)
		bits := api.bigField.ToBits(r)
		lo := api.FromBinary(bits[:numBitsPerVar]...)
		hi := api.FromBinary(bits[numBitsPerVar:256]...)
		return Bytes32{Val: [2]Variable{lo, hi}}
	case Variable:
		return Bytes32{Val: [2]Variable{v, 0}}
	}
	panic(fmt.Errorf("unsupported casting from %T to Bytes32", i))
}

// ToBigVariable casts a Bytes32 or a Variable type to a BigVariable type
func (api *CircuitAPI) ToBigVariable(i interface{}) *BigVariable {
	switch v := i.(type) {
	case Bytes32:
		// Recompose the Bytes32 into BigField.NbLimbs limbs
		bits := v.toBinaryVars(api.g)
		f := BigField{}
		limbs := make([]Variable, f.NbLimbs())
		b := f.BitsPerLimb()
		limbs[0] = api.FromBinary(bits[:b]...)
		limbs[1] = api.FromBinary(bits[b : 2*b]...)
		limbs[2] = api.FromBinary(bits[2*b:]...)
		limbs[3], limbs[4], limbs[5] = 0, 0, 0
		el := api.bigField.NewElement(limbs)
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
		api.AssertIsEqual(v.Val[1], 0)
		return v.Val[0]
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

func (api *CircuitAPI) AssertIsEqualBig(a, b *BigVariable) {
	fmt.Printf("a %+v\nb %+v\n", a.Limbs, b.Limbs)
	api.bigField.AssertIsEqual(a.Element, b.Element)
}
