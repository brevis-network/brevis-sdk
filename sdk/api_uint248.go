package sdk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type Uint248 struct {
	Val frontend.Variable
}

var _ CircuitVariable = Uint248{}

// newU248 constructs a new Uint248 instance.
// It is important that the input value `v` is at most 248 bits wide.
func newU248(v frontend.Variable) Uint248 {
	return Uint248{Val: v}
}

func newU248s(vs ...frontend.Variable) List[Uint248] {
	ret := make([]Uint248, len(vs))
	for i, v := range vs {
		ret[i] = newU248(v)
	}
	return ret
}

// ConstUint248 initializes a constant Uint248. This function does not generate
// circuit wires and should only be used outside of circuit. Supports all int and
// uint variants, bool, []byte (big-endian), *big.Int, and string inputs. If
// input is string, this function uses *big.Int SetString function to interpret
// the string
func ConstUint248(i interface{}) Uint248 {
	ensureNotCircuitVariable(i)
	v := fromInterface(i)
	if v.Sign() < 0 {
		panic("cannot initialize Uint248 with negative number")
	}
	if v.BitLen() > 248 {
		panic("cannot initialize Uint248 with bit length > 248")
	}
	return newU248(v)
}

// ParseEventID initializes a circuit Uint248 from bytes. Only the first 6 bytes
// of the event id is used to save space. This function does not generate circuit
// wires and should only be used outside of circuit.
func ParseEventID(b []byte) Uint248 {
	return newU248(new(big.Int).SetBytes(b[:6]))
}

func (v Uint248) Values() []frontend.Variable {
	return []frontend.Variable{v.Val}
}

func (v Uint248) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != 1 {
		panic("Uint248.FromValues only takes 1 param")
	}
	v.Val = vs[0]
	return v
}

func (v Uint248) NumVars() uint32 { return 1 }

func (v Uint248) String() string { return fmt.Sprintf("%d", v.Val) }

type Uint248API struct {
	g frontend.API `gnark:"-"`
}

func newUint248API(api frontend.API) *Uint248API {
	return &Uint248API{api}
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to a Uint248
func (api *Uint248API) FromBinary(vs ...Uint248) Uint248 {
	if len(vs) > 248 {
		panic(fmt.Sprintf("cannot construct Uint248 from binary of size %d bits", len(vs)))
	}
	vars := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		vars[i] = v.Val
	}
	return newU248(api.g.FromBinary(vars...))
}

// ToBinary decomposes the input v to a list (size n) of little-endian binary
// digits
func (api *Uint248API) ToBinary(v Uint248, n int) List[Uint248] {
	b := api.g.ToBinary(v.Val, n)
	ret := make([]Uint248, n)
	for i, bit := range b {
		ret[i] = newU248(bit)
	}
	return ret
}

// Add returns a + b. Overflow can happen if a + b > 2^248
func (api *Uint248API) Add(a, b Uint248, other ...Uint248) Uint248 {
	vo := make([]frontend.Variable, len(other))
	for i, o := range other {
		vo[i] = o.Val
	}
	return newU248(api.g.Add(a.Val, b.Val, vo...))
}

// Sub returns a - b. Underflow can happen if b > a
func (api *Uint248API) Sub(a, b Uint248) Uint248 {
	return newU248(api.g.Sub(a.Val, b.Val))
}

// Mul returns a * b. Overflow can happen if a * b > 2^248
func (api *Uint248API) Mul(a, b Uint248) Uint248 {
	return newU248(api.g.Mul(a.Val, b.Val))
}

// Div computes the standard unsigned integer division (like Go) and returns the
// quotient and remainder. Uses QuoRemHint
func (api *Uint248API) Div(a, b Uint248) (quotient, remainder Uint248) {
	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a.Val, b.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize Div hint instance: %s", err.Error()))
	}
	q, r := out[0], out[1]
	orig := api.g.Add(api.g.Mul(q, b.Val), r)
	api.g.AssertIsEqual(orig, a.Val)
	api.g.IsZero(api.g.Sub(q, api.g.Div(a.Val, b.Val)))
	return newU248(q), newU248(r)
}

// Sqrt returns √a. Uses SqrtHint
func (api *Uint248API) Sqrt(a Uint248) Uint248 {
	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a.Val)
	if err != nil {
		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
	}
	s := out[0]
	api.g.AssertIsLessOrEqual(api.g.Mul(s, s), a.Val) // s**2 <= a
	incS := api.g.Add(s, 1)
	next := api.g.Mul(incS, incS)
	api.g.IsZero(api.g.Add(api.g.Cmp(a.Val, next), 1)) // a < (s+1)**2
	return newU248(s)
}

// IsZero returns 1 if a == 0, and 0 otherwise
func (api *Uint248API) IsZero(a Uint248) Uint248 {
	return newU248(api.g.IsZero(a.Val))
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Uint248API) IsEqual(a, b Uint248) Uint248 {
	return api.IsZero(api.Sub(a, b))
}

func (api *Uint248API) cmp(a, b Uint248) Uint248 {
	return newU248(api.g.Cmp(a.Val, b.Val))
}

// IsLessThan returns 1 if a < b, and 0 otherwise
func (api *Uint248API) IsLessThan(a, b Uint248) Uint248 {
	return api.IsZero(api.Add(api.cmp(a, b), newU248(1)))
}

// IsGreaterThan returns 1 if a > b, and 0 otherwise
func (api *Uint248API) IsGreaterThan(a, b Uint248) Uint248 {
	return api.IsLessThan(b, a)
}

// And returns 1 if a && b [&& other[0] [&& other[1]...]] is true, and 0 otherwise
func (api *Uint248API) And(a, b Uint248, other ...Uint248) Uint248 {
	res := api.g.And(a.Val, b.Val)
	for _, v := range other {
		res = api.g.And(res, v.Val)
	}
	return newU248(res)
}

// Or returns 1 if a || b [|| other[0] [|| other[1]...]] is true, and 0 otherwise
func (api *Uint248API) Or(a, b Uint248, other ...Uint248) Uint248 {
	res := api.g.Or(a.Val, b.Val)
	for _, v := range other {
		res = api.g.Or(res, v.Val)
	}
	return newU248(res)
}

// Not returns 1 if a is 0, and 0 if a is 1. The user must make sure a is either
// 0 or 1
func (api *Uint248API) Not(a Uint248) Uint248 {
	return api.IsZero(a)
}

// Select returns a if s == 1, and b if s == 0
func (api *Uint248API) Select(s Uint248, a, b Uint248) Uint248 {
	return newU248(api.g.Select(s.Val, a.Val, b.Val))
}

// AssertIsEqual asserts a == b
func (api *Uint248API) AssertIsEqual(a, b Uint248) {
	api.g.AssertIsEqual(a.Val, b.Val)
}

// AssertIsLessOrEqual asserts a <= b
func (api *Uint248API) AssertIsLessOrEqual(a, b Uint248) {
	api.g.AssertIsLessOrEqual(a.Val, b.Val)
}

// AssertIsDifferent asserts a != b
func (api *Uint248API) AssertIsDifferent(a, b Uint248) {
	api.g.AssertIsDifferent(a.Val, b.Val)
}
