package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

type Uint248 struct {
	Val frontend.Variable
}

func newU248(v frontend.Variable) Uint248 {
	return Uint248{Val: v}
}

// ParseAddress initializes a circuit Uint248 from an address type. This
// function is not a circuit g and should only be used outside of circuit to
// initialize constant circuit variables
func ParseAddress(addr [20]byte) Uint248 {
	return newU248(new(big.Int).SetBytes(addr[:]))
}

// ParseBytes initializes a circuit Uint248 from a bytes type. Panics if len(b)
// > 31. This function is not a circuit g and should only be used outside of
// circuit to initialize constant circuit variables
func ParseBytes(b []byte) Uint248 {
	if len(b) > 31 {
		panic(fmt.Errorf("byte slice of size %d cannot fit into one Uint248. use ParseBytes32 instead", len(b)))
	}
	return newU248(new(big.Int).SetBytes(b))
}

// ParseBool initializes a circuit Uint248 from a bool type. This function is
// not a circuit g and should only be used outside of circuit to initialize
// constant circuit variables
func ParseBool(b bool) Uint248 {
	if b {
		return newU248(1)
	}
	return newU248(0)
}

// ParseEventID initializes a circuit Uint248 from bytes. Only the first 6 bytes
// of the event id is used to save space. This function is not a circuit g and
// should only be used outside of circuit to initialize constant circuit
// variables
func ParseEventID(b []byte) Uint248 {
	return newU248(new(big.Int).SetBytes(b[:6]))
}

func (v Uint248) Values() []frontend.Variable {
	return []frontend.Variable{v.Val}
}

func (v Uint248) SetValues(vs ...frontend.Variable) {
	if len(vs) != 1 {
		panic("Uint248.SetValues only takes len 1 slice")
	}
	v.Val = vs[0]
}

type Uint248API struct {
	*CircuitAPI
}

func NewUint248API(api *CircuitAPI) Uint248API {
	return Uint248API{api}
}

func (api *Uint248API) Add(a, b Uint248, other ...Uint248) Uint248 {
	vo := make([]frontend.Variable, len(other))
	for i, o := range other {
		vo[i] = o.Val
	}
	return newU248(api.g.Add(a.Val, b.Val, vo...))
}

func (api *Uint248API) Sub(a, b Uint248) Uint248 {
	return newU248(api.g.Sub(a.Val, b.Val))
}

func (api *Uint248API) Mul(a, b Uint248) Uint248 {
	return newU248(api.g.Mul(a.Val, b.Val))
}

// Div computes the standard unsigned integer division a / b and
// its remainder. Uses QuoRemHint.
func (api *Uint248API) Div(a, b Uint248) (quotient, remainder Uint248) {
	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a, b)
	if err != nil {
		panic(fmt.Errorf("failed to initialize Div hint instance: %s", err.Error()))
	}
	q, r := out[0], out[1]
	orig := api.g.Add(api.g.Mul(q, b), r)
	api.g.AssertIsEqual(orig, a)
	return newU248(q), newU248(r)
}

// Sqrt returns √a. Uses SqrtHint
func (api *Uint248API) Sqrt(a Uint248) Uint248 {
	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return newU248(out[0])
}

// Equal returns 1 if a == b, and 0 otherwise
func (api *Uint248API) Equal(a, b Uint248) Uint248 {
	return api.IsZero(api.Sub(a, b))
}

func (api *Uint248API) Cmp(a, b Uint248) Uint248 {
	return newU248(api.g.Cmp(a.Val, b.Val))
}

// LT returns 1 if a < b, and 0 otherwise
func (api *Uint248API) LT(a, b Uint248) Uint248 {
	return api.IsZero(api.Add(api.Cmp(a, b), newU248(1)))
}

// GT returns 1 if a > b, and 0 otherwise
func (api *Uint248API) GT(a, b Uint248) Uint248 {
	return api.IsZero(api.Sub(newU248(api.Cmp(a, b)), newU248(1)))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *Uint248API) And(a, b Uint248, other ...Uint248) Uint248 {
	res := api.g.And(a.Val, b.Val)
	for _, v := range other {
		api.g.And(res, v)
	}
	return newU248(res)
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *Uint248API) Or(a, b Uint248, other ...Uint248) Uint248 {
	res := api.g.Or(a.Val, b.Val)
	for _, v := range other {
		api.g.Or(res, v.Val)
	}
	return newU248(res)
}

// Not returns 1 if `a` is 0, and 0 if `a` is 1. The user must make sure `a` is
// either 0 or 1
func (api *Uint248API) Not(a Uint248) Uint248 {
	return api.IsZero(a)
}

func (api *Uint248API) Select(s Uint248, a, b Uint248) Uint248 {
	return newU248(api.g.Select(s.Val, a.Val, b.Val))
}

func (api *Uint248API) IsZero(a Uint248) Uint248 {
	return newU248(api.g.IsZero(a.Val))
}

func (api *Uint248API) AssertIsEqual(a, b Uint248) {
	api.g.AssertIsEqual(a.Val, b.Val)
}
