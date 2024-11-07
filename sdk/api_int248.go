package sdk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type Int248 struct {
	// Val encodes the entire int248 including the sign bit as a uint
	Val frontend.Variable
	// SignBit caches the sign bit signal. 0 if positive, 1 if negative. It could be
	// uninitialized.
	SignBit    frontend.Variable
	signBitSet bool `gnark:"-"`
}

// newI248 constructs a new Int248 instance.
// It is important that the input value `v` is at most 248 bits wide.
func newI248(v ...frontend.Variable) Int248 {
	if len(v) > 2 {
		panic(fmt.Sprintf("newI248 expects 1 or 2 variables, got %d", len(v)))
	}
	ret := Int248{Val: v[0]}
	if len(v) > 1 {
		ret.SignBit = v[1]
		ret.signBitSet = true
	}
	return ret
}

// ConstInt248 initializes a constant Int248. This function does not generate
// circuit wires and should only be used outside of circuit. The input big int
// can be negative
func ConstInt248(v *big.Int) Int248 {
	if v.BitLen() >= 248 {
		panic("cannot initialize Int248 with bit length > 248")
	}

	abs := new(big.Int).Abs(v)
	absBits := decomposeBitsExactOfAbs(abs)

	if v.Sign() < 0 {
		bits := twosComplement(absBits, 248)
		a := recompose(bits, 1)
		return newI248(a, 1)
	}

	return newI248(abs, 0)
}

var _ CircuitVariable = Int248{}

func (v Int248) Values() []frontend.Variable {
	return []frontend.Variable{v.Val}
}

func (v Int248) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != 1 {
		panic("Int248.FromValues only takes 1 param")
	}
	v.Val = vs[0]
	v.signBitSet = false
	return v
}

func (v Int248) NumVars() uint32 { return 1 }

func (v Int248) String() string {
	b, ok := v.Val.(*big.Int)
	if !ok {
		return ""
	}
	bits := decompose[uint](b, 1, 248)
	signBit := bits[len(bits)-1]

	abs := new(big.Int).Set(b)
	sign := ""
	if signBit == 1 {
		abs = recompose(twosComplement(bits, 248), 1)
		sign = "-"
	}
	return fmt.Sprintf("%s%d", sign, abs)
}

type Int248API struct {
	g frontend.API `gnark:"-"`
}

func newInt248API(api frontend.API) *Int248API {
	return &Int248API{api}
}

// ToBinary decomposes the input v to a list (size n) of little-endian binary digits
func (api *Int248API) ToBinary(v Int248) List[Uint248] {
	return newU248s(api.g.ToBinary(v.Val, 248)...)
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to an Int248. The MSB (most significant bit) of the input is
// interpreted as the sign bit
func (api *Int248API) FromBinary(vs ...Uint248) Int248 {
	if len(vs) > 248 {
		panic(fmt.Sprintf("cannot construct Int248 from binary of size %d bits", len(vs)))
	}

	var list List[Uint248] = vs
	values := list.Values()

	signBit := values[len(values)-1]
	for i := len(values); i < 248; i++ {
		//rest[i] = api.g.Select(signBit, 1, 0)
		values = append(values, signBit)
	}

	ret := Int248{}
	ret.Val = api.g.FromBinary(values...)
	ret.SignBit = signBit
	ret.signBitSet = true

	return ret
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Int248API) IsEqual(a, b Int248) Uint248 {
	eq := api.g.IsZero(api.g.Sub(a.Val, b.Val))
	return newU248(eq)
}

// IsLessThan returns 1 if a < b, and 0 otherwise
func (api *Int248API) IsLessThan(a, b Int248) Uint248 {
	a = api.ensureSignBit(a)
	b = api.ensureSignBit(b)

	cmp := api.g.Cmp(a.Val, b.Val)
	isLtAsUint := api.g.IsZero(api.g.Add(cmp, 1))

	isLt := api.g.Lookup2(
		a.SignBit, b.SignBit,
		isLtAsUint, // a, b both pos
		1,          // a neg, b pos
		0,          // a pos, b neg
		isLtAsUint, // a, b both neg
	)

	return newU248(isLt)
}

// IsGreaterThan returns 1 if a > b, and 0 otherwise
func (api *Int248API) IsGreaterThan(a, b Int248) Uint248 {
	return api.IsLessThan(b, a)
}

// IsZero returns 1 if a == 0, and 0 otherwise
func (api *Int248API) IsZero(a Int248) Uint248 {
	isZero := api.g.IsZero(a.Val)
	return newU248(isZero)
}

// ABS returns the absolute value of a
// func (api *Int248API) ABS(a Int248) Uint248 {
// 	bs := api.ToBinary(a)
// 	signBit := bs[247] // ToBinary returns little-endian bits, the last bit is sign
// 	flipped := make([]frontend.Variable, len(bs))
// 	for i, v := range bs {
// 		flipped[i] = api.g.IsZero(v.Val)
// 	}
// 	absWhenOrigIsNeg := api.g.Add(1, api.g.FromBinary(flipped...))
// 	abs := api.g.Select(signBit.Val, absWhenOrigIsNeg, a.Val)
// 	return newU248(abs)
// }

// ABS returns the absolute value of a
func (api *Int248API) ABS(a Int248) Uint248 {
	a = api.ensureSignBit(a)
	resultIfNonNeg := a.Val
	resultIfNeg := api.g.Sub(new(big.Int).Lsh(big.NewInt(1), 248), a.Val)
	result := api.g.Select(a.SignBit, resultIfNeg, resultIfNonNeg)
	return newU248(result)
}

//func (api *Int248API) Add(a, b Int248) Int248 {
//	panic("unimplemented")
//	return Int248{}
//}
//
//func (api *Int248API) Sub(a, b Int248) Int248 {
//	panic("unimplemented")
//	return Int248{}
//}
//
//func (api *Int248API) Mul(a, b Int248) Int248 {
//	panic("unimplemented")
//	return Int248{}
//}
//
//func (api *Int248API) Div(a, b Int248) Int248 {
//	panic("unimplemented")
//	return Int248{}
//}

// Select returns a if s == 1, and b if s == 0
func (api *Int248API) Select(s Uint248, a, b Int248) Int248 {
	v := Int248{}
	v.Val = api.g.Select(s.Val, a.Val, b.Val)
	if a.signBitSet && b.signBitSet {
		v.SignBit = api.g.Select(s.Val, a.SignBit, b.SignBit)
		v.signBitSet = true
	}
	return v
}

// AssertIsEqual asserts a == b
func (api *Int248API) AssertIsEqual(a, b Int248) {
	api.g.AssertIsEqual(a.Val, b.Val)
}

// AssertIsDifferent asserts a != b
func (api *Int248API) AssertIsDifferent(a, b Int248) {
	api.g.AssertIsDifferent(a.Val, b.Val)
}

func (api *Int248API) ensureSignBit(v Int248) Int248 {
	if v.signBitSet {
		return v
	}
	bin := api.g.ToBinary(v.Val, 248)
	v.SignBit = bin[247]
	v.signBitSet = true
	return v
}
