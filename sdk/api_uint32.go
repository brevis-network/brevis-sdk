package sdk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

type Uint32 struct {
	Val frontend.Variable
}

var _ CircuitVariable = Uint32{}

func newU32(v frontend.Variable) Uint32 {
	return Uint32{Val: v}
}

func newU32s(vs ...frontend.Variable) List[Uint32] {
	ret := make([]Uint32, len(vs))
	for i, v := range vs {
		ret[i] = newU32(v)
	}
	return ret
}

// ConstUint32 initializes a constant Uint32. This function does not generate
// circuit wires and should only be used outside of circuit. Supports all int and
// uint variants, bool, []byte (big-endian), *big.Int, and string inputs. If
// input is string, this function uses *big.Int SetString function to interpret
// the string
func ConstUint32(i interface{}) Uint32 {
	ensureNotCircuitVariable(i)
	return newU32(fromInterface(i))
}

func (v Uint32) Values() []frontend.Variable {
	return []frontend.Variable{v.Val}
}

func (v Uint32) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != 1 {
		panic("Uint32.FromValues only takes 1 param")
	}
	v.Val = vs[0]
	return v
}

func (v Uint32) NumVars() uint32 { return 1 }

func (v Uint32) String() string { return fmt.Sprintf("%d", v.Val) }

type Uint32API struct {
	g frontend.API `gnark:"-"`
}

func newUint32API(api frontend.API) *Uint32API {
	return &Uint32API{api}
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to a Uint32
func (api *Uint32API) FromBinary(vs ...Uint32) Uint32 {
	vars := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		vars[i] = v.Val
	}
	return newU32(api.g.FromBinary(vars...))
}

// ToBinary decomposes the input v to a list (size n) of little-endian binary
// digits
func (api *Uint32API) ToBinary(v Uint32, n int) List[Uint32] {
	b := api.g.ToBinary(v.Val, n)
	ret := make([]Uint32, n)
	for i, bit := range b {
		ret[i] = newU32(bit)
	}
	return ret
}

// Add returns a + b. Overflow can happen if a + b > 2^32
func (api *Uint32API) Add(a, b Uint32, other ...Uint32) Uint32 {
	vo := make([]frontend.Variable, len(other))
	for i, o := range other {
		vo[i] = o.Val
	}
	return newU32(api.g.Add(a.Val, b.Val, vo...))
}

// Sub returns a - b. Underflow can happen if b > a
func (api *Uint32API) Sub(a, b Uint32) Uint32 {
	return newU32(api.g.Sub(a.Val, b.Val))
}

// Mul returns a * b. Overflow can happen if a * b > 2^32
func (api *Uint32API) Mul(a, b Uint32) Uint32 {
	return newU32(api.g.Mul(a.Val, b.Val))
}

// Div computes the standard unsigned integer division (like Go) and returns the
// quotient and remainder. Uses QuoRemHint
func (api *Uint32API) Div(a, b Uint32) (quotient, remainder Uint32) {
	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a.Val, b.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize Div hint instance: %s", err.Error()))
	}
	q, r := out[0], out[1]
	orig := api.g.Add(api.g.Mul(q, b.Val), r)
	api.g.AssertIsEqual(orig, a.Val)
	return newU32(q), newU32(r)
}

// Sqrt returns √a. Uses SqrtHint
func (api *Uint32API) Sqrt(a Uint32) Uint32 {
	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return newU32(out[0])
}

// IsZero returns 1 if a == 0, and 0 otherwise
func (api *Uint32API) IsZero(a Uint32) Uint32 {
	return newU32(api.g.IsZero(a.Val))
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Uint32API) IsEqual(a, b Uint32) Uint32 {
	return api.IsZero(api.Sub(a, b))
}

func (api *Uint32API) cmp(a, b Uint32) Uint32 {
	return newU32(Cmp(api.g, a.Val, b.Val, 32))
}

// IsLessThan returns 1 if a < b, and 0 otherwise
func (api *Uint32API) IsLessThan(a, b Uint32) Uint32 {
	return api.IsZero(api.Add(api.cmp(a, b), newU32(1)))
}

// IsGreaterThan returns 1 if a > b, and 0 otherwise
func (api *Uint32API) IsGreaterThan(a, b Uint32) Uint32 {
	return api.IsZero(api.Sub(api.cmp(a, b), newU32(1)))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *Uint32API) And(a, b Uint32, other ...Uint32) Uint32 {
	res := api.g.And(a.Val, b.Val)
	for _, v := range other {
		res = api.g.And(res, v.Val)
	}
	return newU32(res)
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *Uint32API) Or(a, b Uint32, other ...Uint32) Uint32 {
	res := api.g.Or(a.Val, b.Val)
	for _, v := range other {
		res = api.g.Or(res, v.Val)
	}
	return newU32(res)
}

// Not returns 1 if a is 0, and 0 if a is 1. The user must make sure a is either
// 0 or 1
func (api *Uint32API) Not(a Uint32) Uint32 {
	return api.IsZero(a)
}

// Select returns a if s == 1, and b if s == 0
func (api *Uint32API) Select(s Uint32, a, b Uint32) Uint32 {
	return newU32(api.g.Select(s.Val, a.Val, b.Val))
}

// AssertIsEqual asserts a == b
func (api *Uint32API) AssertIsEqual(a, b Uint32) {
	api.g.AssertIsEqual(a.Val, b.Val)
}

// AssertIsDifferent asserts a != b
func (api *Uint32API) AssertIsDifferent(a, b Uint32) {
	api.g.AssertIsDifferent(a.Val, b.Val)
}
