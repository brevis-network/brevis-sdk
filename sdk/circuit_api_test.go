package sdk

import (
	"github.com/consensys/gnark/frontend"
	"testing"
)

func TestCasting(t *testing.T) {

}

type TestCastingCircuit struct {
	A Bytes32
}

func (c *TestCastingCircuit) Define(gapi frontend.API) error {
	//api := NewCircuitAPI(gapi)

	//v := api.ToVariable(c.A)
	//b := api.ToBigVariable(c.A)
	//
	//b2 := api.ToBigVariable(v)
	//v2 := api.ToVariable(b)
	//
	//api.ToBytes32(v)
	//api.ToBytes32(b)

	return nil
}
