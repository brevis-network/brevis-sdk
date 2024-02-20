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

	c.testSelect()
	c.testComparisons()

	return nil
}

var testInt248 = big.NewInt(12345678912345)
var testI248 = ConstInt248(testUint248)
var testInt248_2 = big.NewInt(22345678912345)
var testI248_2 = ConstInt248(testUint248_2)

func (c *TestInt248APICircuit) testSelect() {
	selected := c.i248.Select(newU248(1), testI248, testI248_2)
	c.g.AssertIsEqual(selected.Val, testInt248)
	selected = c.i248.Select(newU248(0), testI248, testI248_2)
	c.g.AssertIsEqual(selected.Val, testInt248_2)
}

func (c *TestInt248APICircuit) testComparisons() {
	// AssertIsEqual
	c.i248.AssertIsEqual(testI248, testI248)
	// AssertIsDifferent
	c.i248.AssertIsDifferent(testI248, testI248_2)
	// IsZero
	c.g.AssertIsEqual(c.i248.IsZero(testI248).Val, 0)
	c.g.AssertIsEqual(c.i248.IsZero(ConstInt248(0)).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.i248.IsEqual(testI248, testI248).Val, 1)
	c.g.AssertIsEqual(c.i248.IsEqual(testI248, testI248_2).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248, testI248_2).Val, 1)
	// IsGreaterThan
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248, testI248_2).Val, 0)
}
