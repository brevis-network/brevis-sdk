package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestInt248API(t *testing.T) {
	c := &TestInt248APICircuit{}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	check(err)
}

type TestInt248APICircuit struct {
	g    frontend.API
	i248 *Int248API
}

func (c *TestInt248APICircuit) Define(g frontend.API) error {
	c.g = g
	c.i248 = NewInt248API(g)

	c.testBinary()
	c.testSelect()
	c.testComparisons()
	c.testArithmetics()

	return nil
}

var testInt248Pos = big.NewInt(12345678912345)
var testI248Pos = ConstInt248(testInt248Pos)
var testInt248Pos2 = big.NewInt(12345678912346)
var testI248Pos2 = ConstInt248(testInt248Pos2)
var testI248Pos2Bits = flipByGroups(parseBitStr("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010110011101001110011110011100101101101011010"), 1)
var testInt248Neg = big.NewInt(-444644294412797971)
var testI248Neg = ConstInt248(testInt248Neg)
var testInt248Neg2 = big.NewInt(-444644294412797970)
var testI248Neg2 = ConstInt248(testInt248Neg2)
var testI248Neg2Bits = flipByGroups(parseBitStr("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100111010100010011100101111010111100000111101111011111101110"), 1)
var testInt248Pos3 = big.NewInt(444644294412797970)
var testI248Pos3 = ConstInt248(testInt248Pos3)

func (c *TestInt248APICircuit) testBinary() {
	bin := c.i248.ToBinary(testI248Pos2)
	for i, b := range bin {
		c.g.AssertIsEqual(b.Val, testI248Pos2Bits[i])
	}
	recovered := c.i248.FromBinary(bin...)
	c.g.AssertIsEqual(recovered.Val, testI248Pos2.Val)
	c.g.AssertIsEqual(recovered.SignBit, 0)
	recovered2 := c.i248.FromBinary(bin[:45]...)
	c.g.AssertIsEqual(recovered2.Val, recovered.Val)

	bin = c.i248.ToBinary(testI248Neg2)
	for i, b := range bin {
		c.g.AssertIsEqual(b.Val, testI248Neg2Bits[i])
	}
	recovered = c.i248.FromBinary(bin...)
	c.g.AssertIsEqual(recovered.Val, testI248Neg2.Val)
	c.g.AssertIsEqual(recovered.SignBit, 1)
	recovered2 = c.i248.FromBinary(bin[:60]...)
	c.g.AssertIsEqual(recovered2.Val, recovered.Val)

}

func (c *TestInt248APICircuit) testSelect() {
	selected := c.i248.Select(newU248(1), testI248Pos, testI248Neg)
	c.g.AssertIsEqual(selected.Val, testI248Pos.Val)
	selected = c.i248.Select(newU248(0), testI248Pos, testI248Neg)
	c.g.AssertIsEqual(selected.Val, testI248Neg.Val)
}

func (c *TestInt248APICircuit) testComparisons() {
	zero := ConstInt248(big.NewInt(0))
	// AssertIsEqual
	c.i248.AssertIsEqual(testI248Pos, testI248Pos)
	// AssertIsDifferent
	c.i248.AssertIsDifferent(testI248Pos, testI248Neg)
	// IsZero
	c.g.AssertIsEqual(c.i248.IsZero(testI248Pos).Val, 0)
	c.g.AssertIsEqual(c.i248.IsZero(zero).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.i248.IsEqual(testI248Pos, testI248Pos).Val, 1)
	c.g.AssertIsEqual(c.i248.IsEqual(testI248Pos, testI248Neg).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Pos, testI248Pos2).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Neg2).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Pos).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Pos, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, zero).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(zero, testI248Neg).Val, 0)
	// IsGreaterThan
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Pos, testI248Neg).Val, 1)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Neg, testI248Pos).Val, 0)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Neg, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Pos, zero).Val, 1)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(zero, testI248Pos).Val, 0)
}

func (c *TestInt248APICircuit) testArithmetics() {
	abs := c.i248.ABS(testI248Neg2)
	c.g.AssertIsEqual(testI248Pos3.Val, abs.Val)

	abs = c.i248.ABS(ConstInt248(big.NewInt(0)))
	c.g.AssertIsEqual(big.NewInt(0), abs.Val)
}
