package sdk

import (
	"fmt"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/gnark/frontend"
)

// Uint248API contains a set of APIs that can only be used in circuit to perform
// logical and arithmetic operations over circuit variables. It is an extension
// of gnark's frontend.API.
type Uint248API struct {
	frontend.API
	bigField *emulated.Field[BigField]
}

func NewVariableAPI(gapi frontend.API, bigField *emulated.Field[BigField]) *Uint248API {
	api := &Uint248API{API: gapi, bigField: bigField}
	return api
}

func (api *Uint248API) FromBytes32(v Bytes32) Variable {
	api.AssertIsEqual(v.Val[1], 0)
	return newVariable(v.Val[0])
}

func (api *Uint248API) FromBig(v *BigVariable) Variable {
	reduced := api.bigField.Reduce(v.Element)
	api.AssertIsEqual(reduced.Limbs[1], 0)
	api.AssertIsEqual(reduced.Limbs[2], 0)
	return v.Limbs[0]
}

// LT returns 1 if a < b, and 0 otherwise
func (api *Uint248API) LT(a, b Variable) Variable {
	return api.IsZero(api.Add(api.Cmp(a, b), 1))
}

// GT returns 1 if a > b, and 0 otherwise
func (api *Uint248API) GT(a, b Variable) Variable {
	return api.IsZero(api.Sub(api.Cmp(a, b), 1))
}

// IsBetween returns 1 if a < val < b, 0 otherwise
func (api *Uint248API) IsBetween(val, a, b Variable) Variable {
	a = api.Sub(a, 1)
	b = api.Add(b, 1)
	return api.And(api.GT(val, a), api.LT(val, b))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *Uint248API) And(a, b Variable, other ...Variable) Variable {
	res := api.API.And(a, b)
	for _, v := range other {
		api.API.And(res, v)
	}
	return res
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *Uint248API) Or(a, b Variable, other ...Variable) Variable {
	res := api.API.Or(a, b)
	for _, v := range other {
		api.API.Or(res, v)
	}
	return res
}

// Not returns 1 if `a` is 0, and 0 if `a` is 1. The user must make sure `a` is
// either 0 or 1
func (api *Uint248API) Not(a Variable) Variable {
	return api.IsZero(a)
}

// Equal returns 1 if a == b, and 0 otherwise
func (api *Uint248API) Equal(a, b Variable) Variable {
	return api.API.IsZero(api.API.Sub(a, b))
}

// Sqrt returns √a
// Sqrt returns √a. Uses SqrtHint
func (api *Uint248API) Sqrt(a Variable) Variable {
	out, err := api.API.Compiler().NewHint(SqrtHint, 1, a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return out[0]
}

// QuoRem computes the standard unsigned integer division a / b and
// its remainder. Uses QuoRemHint.
func (api *Uint248API) QuoRem(a, b Variable) (quotient, remainder Variable) {
	out, err := api.API.Compiler().NewHint(QuoRemHint, 2, a, b)
	if err != nil {
		panic(fmt.Errorf("failed to initialize QuoRem hint instance: %s", err.Error()))
	}
	quo, rem := out[0], out[1]
	orig := api.API.Add(api.API.Mul(quo, b), rem)
	api.API.AssertIsEqual(orig, a)
	return quo, rem
}
