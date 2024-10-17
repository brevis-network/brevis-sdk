package sdk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

type Uint64 struct {
	Val frontend.Variable
}

var _ CircuitVariable = Uint64{}

func newU64(v frontend.Variable) Uint64 {
	return Uint64{Val: v}
}

func newU64s(vs ...frontend.Variable) List[Uint64] {
	ret := make([]Uint64, len(vs))
	for i, v := range vs {
		ret[i] = newU64(v)
	}
	return ret
}

// ConstUint64 initializes a constant Uint64. This function does not generate
// circuit wires and should only be used outside of circuit. Supports all int and
// uint variants, bool, []byte (big-endian), *big.Int, and string inputs. If
// input is string, this function uses *big.Int SetString function to interpret
// the string
func ConstUint64(i interface{}) Uint64 {
	ensureNotCircuitVariable(i)
	v := fromInterface(i)
	if v.Sign() < 0 {
		panic("cannot initialize Uint64 with negative number")
	}
	if v.BitLen() > 64 {
		panic("cannot initialize Uint64 with bit length > 64")
	}
	return newU64(v)
}

func (v Uint64) Values() []frontend.Variable {
	return []frontend.Variable{v.Val}
}

func (v Uint64) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != 1 {
		panic("Uint64.FromValues only takes 1 param")
	}
	v.Val = vs[0]
	return v
}

func (v Uint64) NumVars() uint32 { return 1 }

func (v Uint64) String() string { return fmt.Sprintf("%d", v.Val) }

type Uint64API struct {
	g frontend.API `gnark:"-"`
}

func newUint64API(api frontend.API) *Uint64API {
	return &Uint64API{api}
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to a Uint64
func (api *Uint64API) FromBinary(vs ...Uint64) Uint64 {
	vars := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		vars[i] = v.Val
	}
	return newU64(api.g.FromBinary(vars...))
}

// ToBinary decomposes the input v to a list (size n) of little-endian binary
// digits
func (api *Uint64API) ToBinary(v Uint64, n int) List[Uint64] {
	b := api.g.ToBinary(v.Val, n)
	ret := make([]Uint64, n)
	for i, bit := range b {
		ret[i] = newU64(bit)
	}
	return ret
}

// Add returns a + b. Overflow can happen if a + b > 2^64
func (api *Uint64API) Add(a, b Uint64, other ...Uint64) Uint64 {
	vo := make([]frontend.Variable, len(other))
	for i, o := range other {
		vo[i] = o.Val
	}
	return newU64(api.g.Add(a.Val, b.Val, vo...))
}

// Sub returns a - b. Underflow can happen if b > a
func (api *Uint64API) Sub(a, b Uint64) Uint64 {
	return newU64(api.g.Sub(a.Val, b.Val))
}

// Mul returns a * b. Overflow can happen if a * b > 2^64
func (api *Uint64API) Mul(a, b Uint64) Uint64 {
	return newU64(api.g.Mul(a.Val, b.Val))
}

// Div computes the standard unsigned integer division (like Go) and returns the
// quotient and remainder. Uses QuoRemHint
func (api *Uint64API) Div(a, b Uint64) (quotient, remainder Uint64) {
	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a.Val, b.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize Div hint instance: %s", err.Error()))
	}
	q, r := out[0], out[1]
	orig := api.g.Add(api.g.Mul(q, b.Val), r)
	api.g.AssertIsEqual(orig, a.Val)
	api.g.IsZero(api.g.Sub(q, api.g.Div(a.Val, b.Val)))
	return newU64(q), newU64(r)
}

// Sqrt returns √a. Uses SqrtHint
func (api *Uint64API) Sqrt(a Uint64) Uint64 {
	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	return newU64(out[0])
}

// IsZero returns 1 if a == 0, and 0 otherwise
func (api *Uint64API) IsZero(a Uint64) Uint64 {
	return newU64(api.g.IsZero(a.Val))
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Uint64API) IsEqual(a, b Uint64) Uint64 {
	return api.IsZero(api.Sub(a, b))
}

func (api *Uint64API) cmp(a, b Uint64) Uint64 {
	return newU64(Cmp(api.g, a.Val, b.Val, 64))
}

// IsLessThan returns 1 if a < b, and 0 otherwise
func (api *Uint64API) IsLessThan(a, b Uint64) Uint64 {
	return api.IsZero(api.Add(api.cmp(a, b), newU64(1)))
}

// IsGreaterThan returns 1 if a > b, and 0 otherwise
func (api *Uint64API) IsGreaterThan(a, b Uint64) Uint64 {
	return api.IsZero(api.Sub(api.cmp(a, b), newU64(1)))
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *Uint64API) And(a, b Uint64, other ...Uint64) Uint64 {
	res := api.g.And(a.Val, b.Val)
	for _, v := range other {
		res = api.g.And(res, v.Val)
	}
	return newU64(res)
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *Uint64API) Or(a, b Uint64, other ...Uint64) Uint64 {
	res := api.g.Or(a.Val, b.Val)
	for _, v := range other {
		res = api.g.Or(res, v.Val)
	}
	return newU64(res)
}

// Not returns 1 if a is 0, and 0 if a is 1. The user must make sure a is either
// 0 or 1
func (api *Uint64API) Not(a Uint64) Uint64 {
	return api.IsZero(a)
}

// Select returns a if s == 1, and b if s == 0
func (api *Uint64API) Select(s Uint64, a, b Uint64) Uint64 {
	return newU64(api.g.Select(s.Val, a.Val, b.Val))
}

// AssertIsEqual asserts a == b
func (api *Uint64API) AssertIsEqual(a, b Uint64) {
	api.g.AssertIsEqual(a.Val, b.Val)
}

// AssertIsDifferent asserts a != b
func (api *Uint64API) AssertIsDifferent(a, b Uint64) {
	api.g.AssertIsDifferent(a.Val, b.Val)
}
