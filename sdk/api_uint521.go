package sdk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
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
	u521Field.Reduce(v.Element)
	return v.Limbs
}

func (v Uint521) FromValues(vs ...frontend.Variable) CircuitVariable {
	n := emulated.ValueOf[Uint521Field](0)
	n.Limbs = vs
	return newU521(&n)
}

func (v Uint521) NumVars() uint32 { return 6 }

func newU521(el *emulated.Element[Uint521Field]) Uint521 {
	return Uint521{el}
}

func ConstUint521(i interface{}) Uint521 {
	v := fromInterface(i)
	el := emulated.ValueOf[Uint521Field](v)
	return newU521(&el)
}

type Uint521API struct {
	g frontend.API
	f *emulated.Field[Uint521Field]
}

func NewUint521API(api frontend.API) *Uint521API {
	f, err := emulated.NewField[Uint521Field](api)
	if err != nil {
		panic(err)
	}
	u521Field = f
	return &Uint521API{g: api, f: f}
}

func (api *Uint521API) FromBinary(vs ...Uint248) Uint521 {
	vars := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		vars[i] = v
	}
	return newU521(api.f.FromBits(vars))
}

func (api *Uint521API) ToBinary(v Uint521, n int) List[Uint248] {
	reduced := api.f.Reduce(v.Element)
	bits := api.f.ToBits(reduced)
	ret := make([]Uint248, n)
	for i := 0; i < n; i++ {
		ret[i] = newU248(bits[i])
	}
	return ret
}

func (api *Uint521API) Add(a, b Uint521) Uint521 {
	return newU521(api.f.Add(a.Element, b.Element))
}

func (api *Uint521API) Sub(a, b Uint521) Uint521 {
	return newU521(api.f.Sub(a.Element, b.Element))
}

func (api *Uint521API) Mul(a, b Uint521) Uint521 {
	return newU521(api.f.Mul(a.Element, b.Element))
}

// Div computes the standard unsigned integer division a / b and
// its remainder. Uses QuoRemBigHint.
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

func (api *Uint521API) Select(s Uint248, a, b Uint521) Uint521 {
	el := api.f.Select(s, a.Element, b.Element)
	return newU521(el)
}

func (api *Uint521API) Equal(a, b Uint521) Uint248 {
	return newU248(api.f.IsZero(api.f.Sub(a.Element, b.Element)))
}

func (api *Uint521API) AssertIsEqual(a, b Uint521) {
	api.f.AssertIsEqual(a.Element, b.Element)
}

func (api *Uint521API) AssertIsLessOrEqual(a, b Uint521) {
	_a := api.f.Reduce(a.Element)
	_b := api.f.Reduce(b.Element)
	api.f.AssertIsLessOrEqual(_a, _b)
}
