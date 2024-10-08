package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestUint248API(t *testing.T) {
	c := &TestUint248APICircuit{}
	err := test.IsSolved(c, c, ecc.BN254.ScalarField())
	check(err)
}

type TestUint248APICircuit struct {
	g    frontend.API
	u248 *Uint248API
}

func (c *TestUint248APICircuit) Define(g frontend.API) error {
	c.g = g
	c.u248 = newUint248API(g)

	c.testBinary()
	c.testSelect()
	c.testArithmetic()
	c.testComparisons()
	c.testLogical()

	return nil
}

var testUint248 = big.NewInt(12345678912345)
var testU248 = ConstUint248(testUint248)
var testUint248_2 = big.NewInt(22345678912345)
var testU248_2 = ConstUint248(testUint248_2)
var testUint248_bits = "000010110011101001110011110011100101101101011001"

func (c *TestUint248APICircuit) testBinary() {
	v := c.u248.ToBinary(testU248, 48)
	bits := flipByGroups(parseBitStr(testUint248_bits), 1)
	for i, b := range bits {
		c.g.AssertIsEqual(b, v[i].Val)
	}

	num := c.u248.FromBinary(v...)
	c.g.AssertIsEqual(num.Val, testUint248)
}

func (c *TestUint248APICircuit) testSelect() {
	selected := c.u248.Select(ConstUint248(1), testU248, testU248_2)
	c.g.AssertIsEqual(selected.Val, testUint248)

	selected = c.u248.Select(ConstUint248(0), testU248, testU248_2)
	c.g.AssertIsEqual(selected.Val, testUint248_2)
}

func (c *TestUint248APICircuit) testArithmetic() {
	// Add
	c.g.AssertIsEqual(
		c.u248.Add(testU248, testU248_2).Val,
		new(big.Int).Add(testUint248, testUint248_2),
	)
	// Sub
	c.g.AssertIsEqual(
		c.u248.Sub(testU248_2, testU248).Val,
		new(big.Int).Sub(testUint248_2, testUint248),
	)
	// Mul
	c.g.AssertIsEqual(
		c.u248.Mul(testU248_2, testU248).Val,
		new(big.Int).Mul(testUint248, testUint248_2),
	)
	// Div
	q, r := c.u248.Div(testU248_2, testU248)
	qe, re := new(big.Int).QuoRem(testUint248_2, testUint248, new(big.Int))
	c.g.AssertIsEqual(q.Val, qe)
	c.g.AssertIsEqual(r.Val, re)

	// Sqrt
	c.g.AssertIsEqual(c.u248.Sqrt(testU248).Val, new(big.Int).Sqrt(testUint248))
}

func (c *TestUint248APICircuit) testComparisons() {
	// AssertIsEqual
	c.u248.AssertIsEqual(testU248, testU248)
	// AssertIsDifferent
	c.u248.AssertIsDifferent(testU248, testU248_2)
	// IsZero
	c.g.AssertIsEqual(c.u248.IsZero(testU248).Val, 0)
	c.g.AssertIsEqual(c.u248.IsZero(ConstUint248(0)).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.u248.IsEqual(testU248, testU248).Val, 1)
	c.g.AssertIsEqual(c.u248.IsEqual(testU248, testU248_2).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.u248.IsLessThan(testU248, testU248_2).Val, 1)
	// IsGreaterThan
	c.g.AssertIsEqual(c.u248.IsGreaterThan(testU248, testU248_2).Val, 0)
}

func (c *TestUint248APICircuit) testLogical() {
	one := ConstUint248(1)
	zero := ConstUint248(0)
	// And
	c.g.AssertIsEqual(c.u248.And(one, one, one).Val, 1)
	c.g.AssertIsEqual(c.u248.And(one, one, zero).Val, 0)
	// Or
	c.g.AssertIsEqual(c.u248.Or(one, one, zero).Val, 1)
	c.g.AssertIsEqual(c.u248.Or(zero, zero, zero).Val, 0)
	// Not
	c.g.AssertIsEqual(c.u248.Not(one).Val, 0)
	c.g.AssertIsEqual(c.u248.Not(zero).Val, 1)
}
