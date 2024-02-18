package sdk

import "github.com/consensys/gnark/frontend"

type Int248 struct {
}

func ConstInt248() {

}

type Int248API struct {
	g frontend.API
}

func NewInt248API(api frontend.API) *Int248API {
	return &Int248API{}
}
