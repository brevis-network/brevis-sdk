package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

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

func (b *Uint521) Values() []frontend.Variable {
	return b.Limbs // TODO might be problematic if the element isn't reduced first
}

func (b *Uint521) SetValues(vs []frontend.Variable) {
	b.Limbs = vs
}

func newU521(el *emulated.Element[Uint521Field]) Uint521 {
	return Uint521{el}
}

func ParseBigBytes(data []byte) Uint521 {
	if len(data) > 64 {
		panic(fmt.Errorf("ParseBigBytes called with data of length %d", len(data)))
	}
	el := emulated.ValueOf[Uint521Field](data)
	return newU521(&el)
}

type Uint521API struct {
	*CircuitAPI
	f *emulated.Field[Uint521Field]
}

func NewUint521API(api *CircuitAPI) Uint521API {
	f, err := emulated.NewField[Uint521Field](api.g)
	if err != nil {
		panic(err)
	}
	return Uint521API{CircuitAPI: api, f: f}
}

func (api *Uint521API) FromUin248(v Uint248) Uint521 {
	el := api.f.NewElement(v.Val)
	return newU521(el)
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

func (api *Uint521API) AssertIsEqual(a, b Uint521) {
	api.f.AssertIsEqual(a.Element, b.Element)
}

func (api *Uint521API) SelectBig(s Variable, a, b *BigVariable) *BigVariable {
	el := api.bigField.Select(s, a.Element, b.Element)
	return newBigVariable(el)
}

func (api *Uint521API) EqualBig(a, b *BigVariable) Variable {
	return api.bigField.IsZero(api.bigField.Sub(a.Element, b.Element))
}
