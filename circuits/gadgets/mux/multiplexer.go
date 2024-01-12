package mux

import (
	"github.com/consensys/gnark/frontend"
)

func Multiplex(
	api frontend.API,
	selector frontend.Variable,
	wIn int,
	nIn int,
	input [][]frontend.Variable,
) (output []frontend.Variable) {
	mask, outputSuccess := decode(api, nIn, selector)
	for i := 0; i < wIn; i++ {
		ep := dotProduct(api, nIn, input[i], mask)
		output = append(output, ep)
	}
	api.AssertIsEqual(outputSuccess, 1)
	return
}

// decodes the input selector num into a bit mask
// e.g. width 8 select 3 -> 00010000
func decode(api frontend.API, width int, input frontend.Variable) (output []frontend.Variable, outputSuccess frontend.Variable) {
	outputSuccess = 0
	for i := 0; i < width; i++ {
		value := isEqual(api, i, input)
		output = append(output, value)
		outputSuccess = api.Add(outputSuccess, value)
	}
	api.AssertIsBoolean(outputSuccess)
	return
}

func dotProduct(api frontend.API, width int, inputA []frontend.Variable, inputB []frontend.Variable) (output frontend.Variable) {
	if len(inputA) != len(inputB) {
		panic("len(inputA) != len(inputB)")
	}
	output = 0
	for i := 0; i < width; i++ {
		output = api.Add(output, api.Mul(inputA[i], inputB[i]))
	}
	return
}

func isEqual(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
