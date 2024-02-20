package sdk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// CircuitAPI contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of g's frontend.API.
type CircuitAPI struct {
	Uint248 *Uint248API
	Uint521 *Uint521API
	Int248  *Int248API
	Bytes32 *Bytes32API

	g      frontend.API
	output []frontend.Variable `gnark:"-"`
}

func NewCircuitAPI(gapi frontend.API) *CircuitAPI {
	return &CircuitAPI{
		g:       gapi,
		Uint248: NewUint248API(gapi),
		Uint521: NewUint521API(gapi),
		Int248:  NewInt248API(gapi),
		Bytes32: NewBytes32API(gapi),
	}
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
func (api *CircuitAPI) OutputBool(v Uint248) {
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
	case *Uint521:
		b := api.ToBytes32(v).toBinaryVars(api.g)
		api.addOutput(b)
	case Uint248:
		b := api.g.ToBinary(v, bitSize)
		api.addOutput(b)
	default:
		panic(fmt.Errorf("cannot output variable of type %T, only supports *Uint521 and Uint248", i))
	}
	fmt.Printf("added uint%d output: %v\n", bitSize, i)
}

// OutputAddress adds an output of solidity address type.
func (api *CircuitAPI) OutputAddress(v Uint248) {
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

func Select[T CircuitVariable](api *CircuitAPI, s Uint248, a, b T) T {
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

func (api *CircuitAPI) ToBytes32(i interface{}) Bytes32 {
	switch v := i.(type) {
	case Uint521:
		api.Uint521.AssertIsLessOrEqual(v, MaxBytes32)
		bits := api.Uint521.ToBinary(v, 32*8)
		lo := api.Uint248.FromBinary(bits[:numBitsPerVar]...)
		hi := api.Uint248.FromBinary(bits[numBitsPerVar:256]...)
		return Bytes32{Val: [2]frontend.Variable{lo.Val, hi.Val}}
	case Uint248:
		return Bytes32{Val: [2]frontend.Variable{v.Val, 0}}
	}
	panic(fmt.Errorf("unsupported casting from %T to Bytes32", i))
}

// ToUint521 casts a Bytes32 or a Uint248 type to a Uint521 type
func (api *CircuitAPI) ToUint521(i interface{}) Uint521 {
	switch v := i.(type) {
	case Bytes32:
		// Recompose the Bytes32 into BigField.NbLimbs limbs
		bits := v.toBinaryVars(api.g)
		f := Uint521Field{}
		limbs := make([]frontend.Variable, f.NbLimbs())
		b := f.BitsPerLimb()
		limbs[0] = api.g.FromBinary(bits[:b]...)
		limbs[1] = api.g.FromBinary(bits[b : 2*b]...)
		limbs[2] = api.g.FromBinary(bits[2*b:]...)
		limbs[3], limbs[4], limbs[5] = 0, 0, 0
		el := api.Uint521.f.NewElement(limbs)
		return newU521(el)
	case Uint248:
		el := api.Uint521.f.NewElement([]frontend.Variable{v.Val, 0, 0, 0, 0, 0})
		return newU521(el)
	}
	panic(fmt.Errorf("unsupported casting from %T to *Uint521", i))
}

// ToUint248 casts a Uint521 or a Bytes32 type to a Uint248 type. It adds
// constraints for checking that the variable being cast does not overflow
// uint248
func (api *CircuitAPI) ToUint248(i interface{}) Uint248 {
	switch v := i.(type) {
	case Bytes32:
		api.g.AssertIsEqual(v.Val[1], 0)
		return newU248(v.Val[0])
	case Uint521:
		max248 := ConstUint521(MaxUint248)
		api.Uint521.AssertIsLessOrEqual(v, max248)
		bits := api.Uint521.ToBinary(v, numBitsPerVar)
		return api.Uint248.FromBinary(bits[:numBitsPerVar]...)
	}
	panic(fmt.Errorf("unsupported casting from %T to Uint248", i))
}

func (api *CircuitAPI) isEqual(a, b frontend.Variable) frontend.Variable {
	return api.g.IsZero(api.g.Sub(a, b))
}
