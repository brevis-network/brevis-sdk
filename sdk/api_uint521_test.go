package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestUint521API(t *testing.T) {
	c := &TestUint521APICircuit{}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(c, c, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
}

type TestUint521APICircuit struct{}

func (c *TestUint521APICircuit) Define(g frontend.API) error {
	api := NewCircuitAPI(g)

	one := ConstUint521([]byte{1})
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ConstUint521(_u256Max.Bytes())
	//checkStrings(u256Max, _u256Max)

	sum := api.Uint521.Add(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(sum, ConstUint521(_sum.Bytes()))
	//checkStrings(sum, _sum)

	diff := api.Uint521.Sub(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(diff, one)
	//checkStrings(diff, one)

	product := api.Uint521.Mul(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(product, ConstUint521(_product.Bytes()))
	//checkStrings(product, _product)

	q, r := api.Uint521.Div(ConstUint521([]byte{4}), ConstUint521([]byte{3}))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, ConstUint521([]byte{1}))

	q, r = api.Uint521.Div(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, one)
	//checkStrings(q, one)

	return nil
}

func checkStrings(a, b fmt.Stringer) {
	if a.String() != b.String() {
		panic(fmt.Errorf("string value not equal %s != %s", a, b))
	}
}
