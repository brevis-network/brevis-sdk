package sdk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestUint32API(t *testing.T) {
	c := &TestUint32APICircuit{}
	err := test.IsSolved(c, c, ecc.BN254.ScalarField())
	check(err)
}

type TestUint32APICircuit struct {
	g   frontend.API
	u32 *Uint32API
}

func (c *TestUint32APICircuit) Define(g frontend.API) error {
	c.g = g
	c.u32 = newUint32API(g)

	c.testBinary()
	c.testSelect()
	c.testArithmetic()
	c.testComparisons()
	c.testLogical()

	return nil
}

var testUint32 = big.NewInt(2070799232)
var testU32 = ConstUint32(testUint32)
var testUint32_2 = big.NewInt(2470799232)
var testU32_2 = ConstUint32(testUint32_2)
var testUint32_bits = "01111011011011011110001110000000"

func (c *TestUint32APICircuit) testBinary() {
	v := c.u32.ToBinary(testU32, 32)
	bits := flipByGroups(parseBitStr(testUint32_bits), 1)
	for i, b := range bits {
		c.g.AssertIsEqual(b, v[i].Val)
	}

	num := c.u32.FromBinary(v...)
	c.g.AssertIsEqual(num.Val, testUint32)
}

func (c *TestUint32APICircuit) testSelect() {
	selected := c.u32.Select(ConstUint32(1), testU32, testU32_2)
	c.g.AssertIsEqual(selected.Val, testUint32)

	selected = c.u32.Select(ConstUint32(0), testU32, testU32_2)
	c.g.AssertIsEqual(selected.Val, testUint32_2)
}

func (c *TestUint32APICircuit) testArithmetic() {
	// Add
	c.g.AssertIsEqual(
		c.u32.Add(testU32, testU32_2).Val,
		new(big.Int).Add(testUint32, testUint32_2),
	)
	// Sub
	c.g.AssertIsEqual(
		c.u32.Sub(testU32_2, testU32).Val,
		new(big.Int).Sub(testUint32_2, testUint32),
	)
	// Mul
	c.g.AssertIsEqual(
		c.u32.Mul(testU32_2, testU32).Val,
		new(big.Int).Mul(testUint32, testUint32_2),
	)
	// Div
	q, r := c.u32.Div(testU32_2, testU32)
	qe, re := new(big.Int).QuoRem(testUint32_2, testUint32, new(big.Int))
	c.g.AssertIsEqual(q.Val, qe)
	c.g.AssertIsEqual(r.Val, re)

	// Sqrt
	c.g.AssertIsEqual(c.u32.Sqrt(testU32).Val, new(big.Int).Sqrt(testUint32))
}

func (c *TestUint32APICircuit) testComparisons() {
	// AssertIsEqual
	c.u32.AssertIsEqual(testU32, testU32)
	// AssertIsDifferent
	c.u32.AssertIsDifferent(testU32, testU32_2)
	// IsZero
	c.g.AssertIsEqual(c.u32.IsZero(testU32).Val, 0)
	c.g.AssertIsEqual(c.u32.IsZero(ConstUint32(0)).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.u32.IsEqual(testU32, testU32).Val, 1)
	c.g.AssertIsEqual(c.u32.IsEqual(testU32, testU32_2).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.u32.IsLessThan(testU32, testU32_2).Val, 1)
	// IsGreaterThan
	c.g.AssertIsEqual(c.u32.IsGreaterThan(testU32, testU32_2).Val, 0)
}

func (c *TestUint32APICircuit) testLogical() {
	one := ConstUint32(1)
	zero := ConstUint32(0)
	// And
	c.g.AssertIsEqual(c.u32.And(one, one, one).Val, 1)
	c.g.AssertIsEqual(c.u32.And(one, one, zero).Val, 0)
	// Or
	c.g.AssertIsEqual(c.u32.Or(one, one, zero).Val, 1)
	c.g.AssertIsEqual(c.u32.Or(zero, zero, zero).Val, 0)
	// Not
	c.g.AssertIsEqual(c.u32.Not(one).Val, 0)
	c.g.AssertIsEqual(c.u32.Not(zero).Val, 1)
}
