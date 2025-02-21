package sdk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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

	const binaryTestBits = "100010101111010110010110011011110101100010110111111101000110110000110001010100011100000011111110100"
	binaryTestNum, _ := new(big.Int).SetString("344046628720840585615695022068", 10)
	binaryTestU521 := api.ToUint521(ConstUint248(binaryTestNum))
	v := api.Uint521.ToBinary(binaryTestU521, 521)
	expectedBits := flipByGroups(parseBitStr(binaryTestBits), 1)
	for i, b := range expectedBits {
		g.AssertIsEqual(b, v[i].Val)
	}
	num := api.ToUint521(api.Uint248.FromBinary(v[:248]...))
	api.Uint521.AssertIsEqual(num, binaryTestU521)

	return nil
}
