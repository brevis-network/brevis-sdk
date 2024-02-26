package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

type Int248 struct {
	// Val encodes the entire int248 including the sign bit as a uint
	Val frontend.Variable
	// SignBit caches the sign bit signal. 0 if positive, 1 if negative. It could be
	// uninitialized.
	SignBit    frontend.Variable
	signBitSet bool
}

func newI248(v ...frontend.Variable) Int248 {
	ret := Int248{Val: v[0]}
	if len(v) > 1 {
		ret.SignBit = v[1]
		ret.signBitSet = true
	}
	return ret
}

func ConstInt248(v *big.Int) Int248 {
	if v.BitLen() > 248 {
		panic("cannot initialize Int248 with bit length > 248")
	}

	abs := new(big.Int).Abs(v)
	absBits := decomposeBitsExact(abs)

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
	return v
}

func (v Int248) NumVars() uint32 { return 1 }

type Int248API struct {
	g frontend.API
}

func NewInt248API(api frontend.API) *Int248API {
	return &Int248API{api}
}

func (api *Int248API) ToBinary(v Int248) List[Uint248] {
	return newU248s(api.g.ToBinary(v.Val, 248)...)
}

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
	a = api.ensureSignBit(a)
	b = api.ensureSignBit(b)

	cmp := api.g.Cmp(a.Val, b.Val)
	isGtAsUint := api.g.IsZero(api.g.Sub(cmp, 1))

	isLt := api.g.Lookup2(
		a.SignBit, b.SignBit,
		isGtAsUint, // a, b both pos
		0,          // a neg, b pos
		1,          // a pos, b neg
		isGtAsUint, // a, b both neg
	)

	return newU248(isLt)
}

func (api *Int248API) IsZero(a Int248) Uint248 {
	isZero := api.g.IsZero(a.Val)
	return newU248(isZero)
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

func (api *Int248API) Select(s Uint248, a, b Int248) Int248 {
	v := Int248{}
	v.Val = api.g.Select(s.Val, a.Val, b.Val)
	if a.signBitSet && b.signBitSet {
		v.SignBit = api.g.Select(s.Val, a.SignBit, b.SignBit)
	}
	return v
}

func (api *Int248API) AssertIsEqual(a, b Int248) {
	api.g.AssertIsEqual(a.Val, b.Val)
}

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
