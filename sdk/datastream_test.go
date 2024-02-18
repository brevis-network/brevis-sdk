package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestDataStream(t *testing.T) {
	vals := []frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c := &TestDataStreamCircuit{
		In: DataPoints[Uint248]{
			Raw:     newU248s(vals...),
			Toggles: []frontend.Variable{1, 1, 1, 1, 1, 0, 0, 0, 0, 0},
		},
	}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestDataStreamCircuit struct {
	In DataPoints[Uint248]
}

func (c *TestDataStreamCircuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)
	u248 := api.Uint248
	in := NewDataStream(api, c.In)

	// uint248 ops

	// Reduce to two variables
	a := Reduce(in, newU248s(0, 0), func(acc List[Uint248], curr Uint248) (newAcc List[Uint248]) {
		return newU248s(u248.Add(acc[0], u248.Add(curr, newU248(1))))
	})
	u248.AssertIsEqual(a[0], newU248(20))
	u248.AssertIsEqual(a[1], newU248(25))

	b := Map(in, func(current Uint248) Uint248 { return u248.Add(current, newU248(1)) }) // 2,3,4,5,6
	b = Filter(b, func(v Uint248) Uint248 { return u248.LT(v, newU248(5)) })             // 2,3,4

	sum := Sum(b)
	u248.AssertIsEqual(sum, newU248(9))

	count := Count(b)
	u248.AssertIsEqual(count, newU248(3))

	b = Map(b, func(v Uint248) Uint248 { return u248.Add(v, newU248(1)) }) // 3,4,5
	max := Max(b)
	u248.AssertIsEqual(max, newU248(5))

	min := Min(b)
	u248.AssertIsEqual(min, newU248(3))

	mean := Mean(b)
	u248.AssertIsEqual(mean, newU248(4))

	AssertEach(b, func(v Uint248) Uint248 {
		return u248.And(u248.GT(v, newU248(2)), u248.LT(v, newU248(5)))
	})

	AssertSorted(b, func(a, b Uint248) Uint248 { return u248.IsEqual(u248.Sub(b, a), newU248(1)) })

	return nil
}
