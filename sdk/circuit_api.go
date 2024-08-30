package sdk

import (
	"fmt"
	"math/big"

	"github.com/brevis-network/zk-utils/circuits/gadgets/keccak"
	"github.com/brevis-network/zk-utils/circuits/gadgets/poseidon"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// CircuitAPI contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of g's frontend.API.
type CircuitAPI struct {
	Uint248 *Uint248API
	Uint521 *Uint521API
	Int248  *Int248API
	Bytes32 *Bytes32API
	Uint32  *Uint32API
	Uint64  *Uint64API

	g                    frontend.API
	output               []variable `gnark:"-"`
	checkInputUniqueness int
}

func NewCircuitAPI(gapi frontend.API) *CircuitAPI {
	return &CircuitAPI{
		g:       gapi,
		Uint248: newUint248API(gapi),
		Uint521: newUint521API(gapi),
		Int248:  newInt248API(gapi),
		Bytes32: newBytes32API(gapi),
		Uint32:  newUint32API(gapi),
		Uint64:  newUint64API(gapi),
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
	_, ok := v.Val[0].(*big.Int)
	dbgPrint(ok, "added bytes32 output: %s\n", v)
}

// OutputBool adds an output of solidity bool type
func (api *CircuitAPI) OutputBool(v Uint248) {
	api.addOutput(api.g.ToBinary(v.Val, 8))
	_, ok := v.Val.(*big.Int)
	dbgPrint(ok, "added bool output: %d\n", v.Val)
}

// OutputUint adds an output of solidity uint_bitSize type where N is in range [8, 248]
// with a step size 8. e.g. uint8, uint16, ..., uint248.
// Panics if a bitSize of non-multiple of 8 is used.
// Panics if the bitSize exceeds 248. For outputting uint256, use OutputBytes32 instead
func (api *CircuitAPI) OutputUint(bitSize int, v Uint248) {
	if bitSize%8 != 0 {
		panic("bitSize must be multiple of 8")
	}
	b := api.g.ToBinary(v.Val, bitSize)
	api.addOutput(b)
	_, ok := v.Val.(*big.Int)
	dbgPrint(ok, "added uint%d output: %d\n", bitSize, v.Val)
}

// OutputUint adds an output of solidity uint_bitSize type where N is in range [8, 248]
// with a step size 8. e.g. uint8, uint16, ..., uint248.
// Panics if a bitSize of non-multiple of 8 is used.
// Panics if the bitSize exceeds 248. For outputting uint256, use OutputBytes32 instead
func (api *CircuitAPI) OutputUint32(bitSize int, v Uint32) {
	if bitSize%8 != 0 || bitSize > 32 {
		panic("bitSize must be multiple of 8")
	}
	b := api.g.ToBinary(v.Val, bitSize)
	api.addOutput(b)
	_, ok := v.Val.(*big.Int)
	dbgPrint(ok, "added uint%d output: %d\n", bitSize, v.Val)
}

// OutputUint adds an output of solidity uint_bitSize type where N is in range [8, 248]
// with a step size 8. e.g. uint8, uint16, ..., uint248.
// Panics if a bitSize of non-multiple of 8 is used.
// Panics if the bitSize exceeds 248. For outputting uint256, use OutputBytes32 instead
func (api *CircuitAPI) OutputUint64(bitSize int, v Uint64) {
	if bitSize%8 != 0 || bitSize > 64 {
		panic("bitSize must be multiple of 8")
	}
	b := api.g.ToBinary(v.Val, bitSize)
	api.addOutput(b)
	_, ok := v.Val.(*big.Int)
	dbgPrint(ok, "added uint%d output: %d\n", bitSize, v.Val)
}

// OutputAddress adds an output of solidity address type.
func (api *CircuitAPI) OutputAddress(v Uint248) {
	api.addOutput(api.g.ToBinary(v.Val, 20*8))
	_, ok := v.Val.(*big.Int)
	dbgPrint(ok, "added address output: %x\n", v.Val)
}

func (api *CircuitAPI) addOutput(bits []variable) {
	// the decomposed v bits are little-endian bits. The way evm uses Keccak expects
	// the input to be big-endian bytes, but the bits in each byte are little endian
	b := flipByGroups(bits, 8)
	api.output = append(api.output, b...)
	dryRunOutput = append(dryRunOutput, bits2Bytes(b)...)
}

// AssertInputsAreUnique Asserts that all input data (Transaction, Receipt,
// StorageSlot) are different from each other
func (api *CircuitAPI) AssertInputsAreUnique() {
	api.checkInputUniqueness = 1
}

// SlotOfArrayElement computes the storage slot for an element in a solidity
// array state variable. arrSlot is the plain slot of the array variable.
// index determines the array index. offset determines the
// offset (in terms of bytes32) within each array element.
func (api *CircuitAPI) SlotOfArrayElement(arrSlot Bytes32, elementSize int, index, offset Uint248) Bytes32 {
	//api.Uint248.AssertIsLessOrEqual(offset, ConstUint248(elementSize))
	o := api.g.Mul(index.Val, elementSize)
	return Bytes32{Val: [2]variable{
		api.g.Add(arrSlot.Val[0], o, offset.Val),
		arrSlot.Val[1],
	}}
}

// SlotOfStructFieldInMapping computes the slot for a struct field
// stored in a solidity mapping. Implements keccak256(h(k) | p) for computing
// mapping or nested mapping's slot where the value is a struct The
// mapping slots are of the order which you would access the solidity mapping. For
// example, to access nested mapping at slot 1 value with m[a][b] and
// subsequently the 4th index of the struct value, use
// SlotOfStructFieldInMapping(1, 4, a, b). If your a and b are not of
// Bytes32 type, cast them to Bytes32 first using api.ToBytes32.
//
// https://docs.soliditylang.org/en/v0.8.24/internals/layout_in_storage.html#mappings-and-dynamic-arrays
func (api *CircuitAPI) SlotOfStructFieldInMapping(
	slot, offset int, valueSlot Bytes32, nestedMappingSlots ...Bytes32) Bytes32 {

	slotBits := decomposeBig(big.NewInt(int64(slot)), 1, 256)

	s := flipByGroups(newVars(slotBits), 8)
	preimage := append(flipByGroups(api.Bytes32.ToBinary(valueSlot).Values(), 8), s...)
	preimagePadded := keccak.PadBits101(api.g, preimage, 1)
	valueSlotBits := keccak.Keccak256Bits(api.g, 1, 0, preimagePadded)

	for _, mk := range nestedMappingSlots {
		preimage = append(flipByGroups(api.Bytes32.ToBinary(mk).Values(), 8), valueSlotBits[:]...)
		preimagePadded = keccak.PadBits101(api.g, preimage, 1)
		valueSlotBits = keccak.Keccak256Bits(api.g, 1, 0, preimagePadded)
	}

	res := api.offsetSlot(valueSlotBits, offset)
	hashByteWiseLE := newU248s(flipByGroups(res[:], 8)...)
	return api.Bytes32.FromBinary(hashByteWiseLE...)
}

func (api *CircuitAPI) offsetSlot(slotBits [256]variable, offset int) [256]variable {
	if offset <= 0 {
		return slotBits
	}
	// Hack: directly doing integer arithmetic on the low limb of the bytes32 because
	// offset is usually very small (< 100). Overflow can only happen if the low limb
	// of the keccak hash is almost full (i.e. 0xffffff...), which is essentially
	// impossible.
	byteWiseLE := newU248s(flipByGroups(slotBits[:], 8)...)
	slot := api.Bytes32.FromBinary(byteWiseLE...)
	slot.Val[0] = api.g.Add(slot.Val[0], offset)

	var ret [256]variable
	copy(ret[:], flipByGroups(api.Bytes32.ToBinary(slot).Values(), 8))
	return ret
}

func Select[T CircuitVariable](api *CircuitAPI, s Uint248, a, b T) T {
	aVals := a.Values()
	bVals := b.Values()
	if len(aVals) != len(bVals) {
		panic(fmt.Errorf("cannot select: inconsistent value length of a (%d) and b (%d)",
			len(aVals), len(bVals)))
	}
	res := make([]variable, len(aVals))
	for i := range aVals {
		res[i] = api.g.Select(s.Val, aVals[i], bVals[i])
	}
	t := *new(T)
	return t.FromValues(res...).(T)
}

// ToBytes32 casts the input to a Bytes32 type. Supports Bytes32, Int248,
// Uint521, and Uint248.
func (api *CircuitAPI) ToBytes32(i interface{}) Bytes32 {
	switch v := i.(type) {
	case Bytes32:
		return v
	case Int248:
		bits := api.Int248.ToBinary(v)
		sign := bits[len(bits)-1]
		// extend the sign bits to fill 256 bits
		for j := len(bits); j < 256; j++ {
			bits = append(bits, sign)
		}
		return api.Bytes32.FromBinary(bits...)
	case Uint521:
		api.Uint521.AssertIsLessOrEqual(v, MaxBytes32)
		bits := api.Uint521.ToBinary(v, 32*8)
		lo := api.Uint248.FromBinary(bits[:numBitsPerVar]...)
		hi := api.Uint248.FromBinary(bits[numBitsPerVar:256]...)
		return Bytes32{Val: [2]variable{lo.Val, hi.Val}}
	case Uint248:
		return Bytes32{Val: [2]variable{v.Val, 0}}
	}
	panic(fmt.Errorf("unsupported casting from %T to Bytes32", i))
}

// ToUint521 casts the input to a Uint521 type. Supports Uint521, Bytes32,
// and Uint248
func (api *CircuitAPI) ToUint521(i interface{}) Uint521 {
	switch v := i.(type) {
	case Uint521:
		return v
	case Bytes32:
		// Recompose the Bytes32 into BigField.NbLimbs limbs
		bits := v.toBinaryVars(api.g)
		f := Uint521Field{}
		limbs := make([]variable, f.NbLimbs())
		b := f.BitsPerLimb()
		limbs[0] = api.g.FromBinary(bits[:b]...)
		limbs[1] = api.g.FromBinary(bits[b : 2*b]...)
		limbs[2] = api.g.FromBinary(bits[2*b:]...)
		limbs[3], limbs[4], limbs[5] = 0, 0, 0
		el := api.Uint521.f.NewElement(limbs)
		return newU521(el)
	case Uint248:
		el := api.Uint521.f.NewElement([]variable{v.Val, 0, 0, 0, 0, 0})
		return newU521(el)
	}
	panic(fmt.Errorf("unsupported casting from %T to Uint521", i))
}

// ToUint248 casts the input to a Uint248 type. Supports Uint32, Uint64, Uint248, Int248,
// Bytes32, and Uint521
func (api *CircuitAPI) ToUint248(i interface{}) Uint248 {
	switch v := i.(type) {
	case Uint248:
		return v
	case Int248:
		return newU248(v.Val)
	case Uint32:
		return newU248(v.Val)
	case Uint64:
		return newU248(v.Val)
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

// ToInt248 casts the input to a Int248 type. Supports Int248, Uint248,
// and Bytes32
func (api *CircuitAPI) ToInt248(i interface{}) Int248 {
	switch v := i.(type) {
	case Int248:
		return v
	case Uint248:
		return newI248(v.Val)
	case Bytes32:
		// hi limb should be zero after removing the sign bit
		hi := v.Val[1]
		hiBits := api.g.ToBinary(hi, 8)
		signBit := hiBits[7]
		isAll0s := api.g.IsZero(hi)
		isAll1s := api.isEqual(hi, 255)
		// if sign bit is 0 then require it is all 0s, if sign bit is 1 then require it
		// is all 1s. This is because if the bytes32 var is actually an int256 that does
		// not overflow int248, its leftmost bits are always either 00000000 for positive
		// numbers or 11111111 for negative numbers.
		ok := api.g.Select(signBit, isAll1s, isAll0s)
		api.g.AssertIsEqual(ok, 1)
		return newI248(v.Val[0])
	}
	panic(fmt.Errorf("unsupported casting from %T to Int248", i))
}

func (api *CircuitAPI) isEqual(a, b variable) variable {
	return api.g.IsZero(api.g.Sub(a, b))
}

func (api *CircuitAPI) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	return api.g.Compiler().NewHint(f, nbOutputs, inputs)
}

func (api *CircuitAPI) NewPoseidon() (poseidon.PoseidonCircuit, error) {
	return poseidon.NewBn254PoseidonCircuit(api.g)
}

func (api *CircuitAPI) NewMiMC() (mimc.MiMC, error) {
	return mimc.NewMiMC(api.g)
}
