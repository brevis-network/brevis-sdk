package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestCircuitAPI(t *testing.T) {
	c := &TestCircuitAPICircuit{}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	check(err)
}

type TestCircuitAPICircuit struct {
	g   frontend.API
	api *CircuitAPI
}

var testU248_a = ConstUint248(1)
var testBytes32_b = ConstBytes32([]byte{1})
var testU521_c = ConstUint521([]byte{1})

func (c *TestCircuitAPICircuit) Define(g frontend.API) error {
	api := NewCircuitAPI(g)
	c.api = api
	c.g = g

	c.testCasting()

	return nil
}

func (c *TestCircuitAPICircuit) testCasting() {
	api := c.api
	c.api.Bytes32.AssertIsEqual(api.ToBytes32(testU248_a), testBytes32_b)
	c.api.Bytes32.AssertIsEqual(api.ToBytes32(testU521_c), testBytes32_b)

	c.api.Uint248.AssertIsEqual(api.ToUint248(testBytes32_b), testU248_a)
	c.api.Uint248.AssertIsEqual(api.ToUint248(testU521_c), testU248_a)

	c.api.Uint521.AssertIsEqual(api.ToUint521(testU248_a), testU521_c)
	c.api.Uint521.AssertIsEqual(api.ToUint521(testBytes32_b), testU521_c)

	one := ConstUint521([]byte{1})
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ConstUint521(_u256Max.Bytes())

	sum := c.api.Uint521.Add(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	c.api.Uint521.AssertIsEqual(sum, ConstUint521(_sum.Bytes()))

	diff := c.api.Uint521.Sub(u256Max, c.api.Uint521.Sub(u256Max, one))
	c.api.Uint521.AssertIsEqual(diff, one)

	product := c.api.Uint521.Mul(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	c.api.Uint521.AssertIsEqual(product, ConstUint521(_product.Bytes()))

	q, r := c.api.Uint521.Div(ConstUint521([]byte{4}), ConstUint521([]byte{3}))
	c.api.Uint521.AssertIsEqual(q, one)
	c.api.Uint521.AssertIsEqual(r, ConstUint521([]byte{1}))

	q, r = c.api.Uint521.Div(u256Max, c.api.Uint521.Sub(u256Max, one))
	c.api.Uint521.AssertIsEqual(q, one)
	c.api.Uint521.AssertIsEqual(r, one)

}
