package sdk

import "github.com/consensys/gnark/frontend"

type Int248 struct {
}

func ConstInt248(i interface{}) Int248 {
	return Int248{} // TODO
}

func (v Int248) Values() []frontend.Variable {
	return []frontend.Variable{} // TODO
}

func (v Int248) SetValues(vs ...frontend.Variable) {
}

type Int248API struct {
	g frontend.API
}

func NewInt248API(api frontend.API) *Int248API {
	return &Int248API{}
}

// IsEqual returns 1 if a == b, and 0 otherwise
func (api *Int248API) IsEqual(a, b Int248) Uint248 {
	return Uint248{} // TODO
}

// IsLessThan returns 1 if a < b, and 0 otherwise
func (api *Int248API) IsLessThan(a, b Int248) Uint248 {
	return Uint248{} // TODO
}

// IsGreaterThan returns 1 if a > b, and 0 otherwise
func (api *Int248API) IsGreaterThan(a, b Int248) Uint248 {
	return Uint248{} // TODO
}

func (api *Int248API) IsZero(a Int248) Uint248 {
	return Uint248{} // TODO
}

func (api *Int248API) Add(a, b Int248) Int248 {
	return Int248{}
}

func (api *Int248API) Sub(a, b Int248) Int248 {
	return Int248{}
}

func (api *Int248API) Mul(a, b Int248) Int248 {
	return Int248{}
}

func (api *Int248API) Div(a, b Int248) Int248 {
	return Int248{}
}

func (api *Int248API) Select(s Uint248, a, b Uint248) Uint248 {
	return newU248(api.g.Select(s.Val, a.Val, b.Val))
}

func (api *Int248API) AssertIsEqual(a, b Int248) {
}

func (api *Int248API) AssertIsDifferent(a, b Int248) {
}
