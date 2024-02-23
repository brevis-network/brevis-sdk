package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestGroupValuesHint(t *testing.T) {
	values := []frontend.Variable{1, 2, 1, 1, 5, 6}
	toggles := []frontend.Variable{1, 1, 0, 1, 0, 1}
	c := &TestGroupValuesHintCircuit{values, toggles}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestGroupValuesHintCircuit struct {
	Values, Toggles []frontend.Variable `gnark:"public"`
}

func (c *TestGroupValuesHintCircuit) Define(api frontend.API) error {
	res, err := computeGroupValuesHint(api, c.Values, c.Toggles)
	check(err)
	fmt.Println("res", res)
	expected := []frontend.Variable{1, 2, 6, 0, 0, 0}
	for i, v := range res {
		api.AssertIsEqual(v, expected[i])
	}
	return nil
}

func TestDataStream(t *testing.T) {
	c := &TestDataStreamCircuit{
		In: DataPoints[Uint248]{
			Raw:     newU248s([]frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...),
			Toggles: []frontend.Variable{1, 1, 1, 1, 1, 0, 0, 0, 0, 0},
		},
		In2: DataPoints[Uint248]{
			Raw: newU248s([]frontend.Variable{
				1, 2, 3, 100,
				5, 2, 7, 101,
				9, 3, 0, 200,
				999, 999,
			}...),
			Toggles: []frontend.Variable{
				1, 1, 1, 1,
				1, 1, 1, 1,
				1, 1, 1, 1,
				0, 0,
			},
		},
	}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestDataStreamCircuit struct {
	In  DataPoints[Uint248]
	In2 DataPoints[Uint248]
	api *CircuitAPI
}

func (c *TestDataStreamCircuit) Define(gapi frontend.API) error {
	c.api = NewCircuitAPI(gapi)

	c.testSimple()
	c.testComplex()

	return nil
}

type MySchema = Tuple3[Bytes32, Uint248, Uint521]

func (c *TestDataStreamCircuit) testComplex() {
	in := NewDataStream(c.api, c.In2)

	// select a range of the underlying data
	// [1, 2, 3, 100, 5, 2, 7, 101, 9, 3, 0, 200]
	trimmed := RangeUnderlying(in, 0, 12)

	// split the data into two windows
	// [[1, 2, 3, 100], [5, 2, 7, 101], [9, 3, 0, 200]]
	windows := WindowUnderlying(trimmed, 4)

	// map the window to MySchema, casting the data to the types I need, discarding
	// the third field in the window in the process
	myCustomDS := Map(windows, func(curr List[Uint248]) MySchema {
		return MySchema{
			F0: c.api.ToBytes32(curr[0]),
			F1: c.api.ToUint248(curr[1]),
			F2: c.api.ToUint521(curr[3]),
		}
	})

	// Define another schema of two fields, then
	// group by the second field in my schema and aggregate the 3rd field
	// result: [[2, 241], [3, 122]]
	reduce := func(acc Tuple2[Uint248, Uint521], curr MySchema) (newAcc Tuple2[Uint248, Uint521]) {
		sum := c.api.Uint521.Add(acc.F1, curr.F2)
		return Tuple2[Uint248, Uint521]{F0: curr.F1, F1: sum}
	}
	getGroupField := func(t MySchema) Uint248 { return t.F1 }
	reducerInit := Tuple2[Uint248, Uint521]{
		F0: ConstUint248(0),
		F1: ConstUint521(0),
	}
	rowsAfterGroupBy, err := GroupBy(myCustomDS, reduce, reducerInit, getGroupField)
	check(err)

	// map the rows and cast the second field to Uint248
	rowsAfterMap := Map(rowsAfterGroupBy, func(curr Tuple2[Uint248, Uint521]) Tuple2[Uint248, Uint248] {
		return Tuple2[Uint248, Uint248]{
			F0: curr.F0,
			F1: c.api.ToUint248(curr.F1),
		}
	})

	// find the max
	maxInit := Tuple2[Uint248, Uint248]{
		F0: ConstUint248(0), // the first field is out group field, it can be anything
		F1: ConstUint248(0),
	}
	isGreater := func(a, b Tuple2[Uint248, Uint248]) Uint248 { return c.api.Uint248.IsGreaterThan(a.F1, b.F1) }
	rowMax := MaxGeneric(rowsAfterMap, maxInit, isGreater)

	c.api.Uint248.AssertIsEqual(rowMax.F0, ConstUint248(2))
	c.api.Uint248.AssertIsEqual(rowMax.F1, ConstUint248(201))

	// find the min
	minInit := Tuple2[Uint248, Uint248]{
		F0: ConstUint248(0), // the first field is out group field, it can be anything
		F1: ConstUint248(MaxUint248),
	}
	isLess := func(a, b Tuple2[Uint248, Uint248]) Uint248 { return c.api.Uint248.IsLessThan(a.F1, b.F1) }
	rowMin := MaxGeneric(rowsAfterMap, minInit, isLess)

	c.api.Uint248.AssertIsEqual(rowMin.F0, ConstUint248(3))
	c.api.Uint248.AssertIsEqual(rowMin.F1, ConstUint248(200))
}

func (c *TestDataStreamCircuit) testSimple() {
	u248 := c.api.Uint248
	in := NewDataStream(c.api, c.In)

	a := Reduce(in, newU248s(0, 0), func(acc List[Uint248], curr Uint248) (newAcc List[Uint248]) {
		return []Uint248{
			u248.Add(acc[0], curr),
			u248.Add(acc[1], u248.Add(curr, newU248(1))),
		}
	})
	u248.AssertIsEqual(a[0], newU248(15))
	u248.AssertIsEqual(a[1], newU248(20))

	b := Map(in, func(current Uint248) Uint248 { return u248.Add(current, newU248(1)) }) // 2,3,4,5,6
	b = Filter(b, func(v Uint248) Uint248 { return u248.IsLessThan(v, newU248(5)) })     // 2,3,4

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
		return u248.And(u248.IsGreaterThan(v, newU248(2)), u248.IsLessThan(v, newU248(6)))
	})

	AssertSorted(b, func(a, b Uint248) Uint248 { return u248.IsEqual(u248.Sub(b, a), newU248(1)) })

}
