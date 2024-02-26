package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
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
	c.testOutput()

	return nil
}

func (c *TestCircuitAPICircuit) testCasting() {
	api := c.api
	api.Bytes32.AssertIsEqual(api.ToBytes32(testU248_a), testBytes32_b)
	api.Bytes32.AssertIsEqual(api.ToBytes32(testU521_c), testBytes32_b)

	api.Uint248.AssertIsEqual(api.ToUint248(testBytes32_b), testU248_a)
	api.Uint248.AssertIsEqual(api.ToUint248(testU521_c), testU248_a)

	api.Uint521.AssertIsEqual(api.ToUint521(testU248_a), testU521_c)
	api.Uint521.AssertIsEqual(api.ToUint521(testBytes32_b), testU521_c)

	one := ConstUint521([]byte{1})
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ConstUint521(_u256Max.Bytes())

	sum := api.Uint521.Add(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(sum, ConstUint521(_sum.Bytes()))

	diff := api.Uint521.Sub(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(diff, one)

	product := api.Uint521.Mul(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(product, ConstUint521(_product.Bytes()))

	q, r := api.Uint521.Div(ConstUint521([]byte{4}), ConstUint521([]byte{3}))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, ConstUint521([]byte{1}))

	q, r = api.Uint521.Div(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, one)
}

func (c *TestCircuitAPICircuit) testOutput() {
	api := c.api
	api.OutputBool(ConstUint248(1))
	api.OutputUint(32, ConstUint248(123))
	api.OutputAddress(ConstUint248(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")))
	api.OutputBytes32(ConstBytes32(common.Hex2Bytes("0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec")))
}
