package sdk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

var u521Field *emulated.Field[Uint521Field]

type Uint521Field struct{}

func (f Uint521Field) NbLimbs() uint     { return 6 }
func (f Uint521Field) BitsPerLimb() uint { return 96 }
func (f Uint521Field) IsPrime() bool     { return true }
func (f Uint521Field) Modulus() *big.Int {
	mod := big.NewInt(1)
	mod.Lsh(mod, 521).Sub(mod, big.NewInt(1))
	return mod
}

type Uint521 struct {
	*emulated.Element[Uint521Field]
}

var _ CircuitVariable = Uint521{}

func (v Uint521) Values() []frontend.Variable {
	return u521Field.Reduce(v.Element).Limbs
}

func (v Uint521) FromValues(vs ...frontend.Variable) CircuitVariable {
	if len(vs) != int(v.NumVars()) {
		panic(fmt.Sprintf("Uint521.FromValues takes %d params", v.NumVars()))
	}
	n := emulated.ValueOf[Uint521Field](0)
	n.Limbs = vs
	v = newU521(&n)
	return v
}

func (v Uint521) NumVars() uint32 { return 6 }

func (v Uint521) String() string {
	f := Uint521Field{}
	n := new(big.Int)
	for i, limb := range v.Element.Limbs {
		b := fromInterface(limb)
		n.Add(n, new(big.Int).Lsh(b, f.BitsPerLimb()*uint(i)))
	}
	return fmt.Sprintf("%d", n.Mod(n, f.Modulus()))
}

func newU521(el *emulated.Element[Uint521Field]) Uint521 {
	return Uint521{el}
}

// ConstUint521 initializes a constant Uint521. This function does not generate
// circuit wires and should only be used outside of circuit. Supports all int and
// uint variants, bool, []byte (big-endian), *big.Int, and string inputs. If
// input is string, this function uses *big.Int SetString function to interpret
// the string
func ConstUint521(i interface{}) Uint521 {
	ensureNotCircuitVariable(i)
	v := fromInterface(i)
	if v.Sign() < 0 {
		panic("cannot initialize Uint521 with negative number")
	}
	if v.BitLen() > 521 {
		panic("cannot initialize Uint521 with bit length > 521")
	}
	el := emulated.ValueOf[Uint521Field](v)
	return newU521(&el)
}

type Uint521API struct {
	g frontend.API                  `gnark:"-"`
	f *emulated.Field[Uint521Field] `gnark:"-"`
}

func newUint521API(api frontend.API) *Uint521API {
	f, err := emulated.NewField[Uint521Field](api)
	if err != nil {
		panic(err)
	}
	u521Field = f
	return &Uint521API{g: api, f: f}
}

// FromBinary interprets the input vs as a list of little-endian binary digits
// and recomposes it to a Uint521
func (api *Uint521API) FromBinary(vs ...Uint248) Uint521 {
	vars := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		vars[i] = v
	}
	return newU521(api.f.FromBits(vars))
}

// ToBinary decomposes the input v to a list (size n) of little-endian binary digits
func (api *Uint521API) ToBinary(v Uint521, n int) List[Uint248] {
	reduced := api.f.Reduce(v.Element)
	bits := api.f.ToBits(reduced)
	ret := make([]Uint248, n)
	for i := 0; i < n; i++ {
		ret[i] = newU248(bits[i])
	}
	return ret
}

// Add returns a + b. The result is reduced by modulo 2^521 - 1.
func (api *Uint521API) Add(a, b Uint521) Uint521 {
	return newU521(api.f.Add(a.Element, b.Element))
}

// Sub returns a - b. Underflow can happen if b > a
func (api *Uint521API) Sub(a, b Uint521) Uint521 {
	return newU521(api.f.Sub(a.Element, b.Element))
}

// Mul returns a * b. The result is reduced by modulo 2^521 - 1.
func (api *Uint521API) Mul(a, b Uint521) Uint521 {
	return newU521(api.f.Mul(a.Element, b.Element))
}

// Div computes the standard unsigned integer division (like Go) and returns the
// quotient and remainder. Uses QuoRemHint
func (api *Uint521API) Div(a, b Uint521) (quotient, remainder Uint521) {
	aEl := api.f.Reduce(a.Element)
	bEl := api.f.Reduce(b.Element)

	out, err := api.f.NewHint(QuoRemBigHint, 2, aEl, bEl)
	if err != nil {
		panic(err)
	}

	q, r := out[0], out[1]
	num := api.f.Mul(q, b.Element)
	num = api.f.Add(num, r)

	api.f.AssertIsEqual(num, a.Element)

	return newU521(q), newU521(r)
}

// Select returns a if s == 1, and b if s == 0
func (api *Uint521API) Select(s Uint248, a, b Uint521) Uint521 {
	el := api.f.Select(s.Val, a.Element, b.Element)
	return newU521(el)
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Uint521API) IsEqual(a, b Uint521) Uint248 {
	return newU248(api.f.IsZero(api.f.Sub(a.Element, b.Element)))
}

// AssertIsEqual asserts a == b
func (api *Uint521API) AssertIsEqual(a, b Uint521) {
	api.f.AssertIsEqual(a.Element, b.Element)
}

// AssertIsLessOrEqual asserts a <= b
func (api *Uint521API) AssertIsLessOrEqual(a, b Uint521) {
	_a := api.f.Reduce(a.Element)
	_b := api.f.Reduce(b.Element)
	api.f.AssertIsLessOrEqual(_a, _b)
}
