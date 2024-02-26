package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
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

var testInt248Pos = big.NewInt(12345678912345)
var testI248Pos = ConstInt248(testInt248Pos)
var testInt248Pos2 = big.NewInt(12345678912346)
var testI248Pos2 = ConstInt248(testInt248Pos2)
var testInt248Neg = common.Hex2Bytes("fffffffffffffffffffffffffffffffffffffffffffffff9d44e5ebc1ef7ed") // -444644294412797971
var testI248Neg = ConstInt248(testInt248Neg)
var testInt248Neg2 = common.Hex2Bytes("fffffffffffffffffffffffffffffffffffffffffffffff9d44e5ebc1ef7ec") // -444644294412797970
var testI248Neg2 = ConstInt248(testInt248Neg2)

func (c *TestInt248APICircuit) testSelect() {
	selected := c.i248.Select(newU248(1), testI248Pos, testI248Neg)
	c.g.AssertIsEqual(selected.Val, testInt248Pos)
	selected = c.i248.Select(newU248(0), testI248Pos, testI248Neg)
	c.g.AssertIsEqual(selected.Val, testInt248Neg)
}

func (c *TestInt248APICircuit) testComparisons() {
	// AssertIsEqual
	c.i248.AssertIsEqual(testI248Pos, testI248Pos)
	// AssertIsDifferent
	c.i248.AssertIsDifferent(testI248Pos, testI248Neg)
	// IsZero
	c.g.AssertIsEqual(c.i248.IsZero(testI248Pos).Val, 0)
	c.g.AssertIsEqual(c.i248.IsZero(ConstInt248(0)).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.i248.IsEqual(testI248Pos, testI248Pos).Val, 1)
	c.g.AssertIsEqual(c.i248.IsEqual(testI248Pos, testI248Neg).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Pos, testI248Pos2).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Neg2).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Pos).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Pos, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsLessThan(testI248Neg, ConstInt248(0)).Val, 1)
	c.g.AssertIsEqual(c.i248.IsLessThan(ConstInt248(0), testI248Neg).Val, 0)
	// IsGreaterThan
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Pos, testI248Neg).Val, 1)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Neg, testI248Pos).Val, 0)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Neg, testI248Neg).Val, 0)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(testI248Pos, ConstInt248(0)).Val, 1)
	c.g.AssertIsEqual(c.i248.IsGreaterThan(ConstInt248(0), testI248Pos).Val, 0)
}
