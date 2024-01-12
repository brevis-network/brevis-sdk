package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestDataStream(t *testing.T) {
	c := &TestDataStreamCircuit{
		In: DataPoints[Variable]{
			Raw:     []Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			Toggles: []Variable{1, 1, 1, 1, 1, 0, 0, 0, 0, 0},
		},
	}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestDataStreamCircuit struct {
	In DataPoints[Variable]
}

func (c *TestDataStreamCircuit) Define(gapi frontend.API) error {
	api := NewCircuitAPI(gapi)
	in := NewDataStream(api, c.In)

	a := in.Reduce2([2]Variable{0, 0}, func(acc [2]Variable, v Variable) (newAcc [2]Variable) {
		return [2]Variable{
			api.Add(acc[0], api.Add(v, 1)),
			api.Add(acc[1], api.Add(v, 2)),
		}
	})
	api.AssertIsEqual(a[0], 20)
	api.AssertIsEqual(a[1], 25)

	b := in.
		Map(func(v Variable) Variable { return api.Add(v, 1) }).  // 2,3,4,5,6
		Filter(func(v Variable) Variable { return api.LT(v, 5) }) // 2,3,4

	sum := b.Sum(func(v Variable) Variable { return v })
	api.AssertIsEqual(sum, 9)

	count := b.Count()
	api.AssertIsEqual(count, 3)

	b = b.Map(func(v Variable) Variable { return api.Add(v, 1) }) // 3,4,5
	max := b.Max(func(v Variable) Variable { return v })
	api.AssertIsEqual(max, 5)

	min := b.Min(func(v Variable) Variable { return v })
	api.AssertIsEqual(min, 3)

	mean := b.Mean(func(v Variable) Variable { return v })
	api.AssertIsEqual(mean, 4)

	//stddev := b.StdDev(func(v Variable) Variable { return v })
	//api.AssertIsEqual(stddev, nil)

	b.AssertEach(func(v Variable) Variable { return api.Between(v, 3, 5) })

	b.AssertSorted(
		func(v Variable) Variable { return v },
		func(a, b Variable) Variable { return api.Equal(api.Sub(b, a), 1) },
	)

	return nil
}
