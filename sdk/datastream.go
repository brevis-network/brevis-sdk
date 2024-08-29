package sdk

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/jedib0t/go-pretty/v6/table"
)

type DataStream[T CircuitVariable] struct {
	api        *CircuitAPI
	underlying []T
	toggles    []frontend.Variable
}

func NewDataStream[T CircuitVariable](api *CircuitAPI, in DataPoints[T]) *DataStream[T] {
	if len(in.Raw) != len(in.Toggles) {
		panic("inconsistent data lengths")
	}
	return &DataStream[T]{
		api:        api,
		underlying: in.Raw,
		toggles:    in.Toggles,
	}
}

func newDataStream[T CircuitVariable](api *CircuitAPI, in []T, toggles []frontend.Variable) *DataStream[T] {
	return &DataStream[T]{
		api:        api,
		underlying: in,
		toggles:    toggles,
	}
}

// Show pretty prints the data stream. Useful for debugging.
func (ds *DataStream[T]) Show() {
	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"#", "data", "toggle"})
	for i, r := range ds.underlying {
		t.AppendRow(table.Row{i, r, ds.toggles[i]})
	}
	t.Render()
}

// GetUnderlying gets an element from the DataStream. Performed on the underlying data
// directly. It also requires the underlying data slot is valid
func GetUnderlying[T CircuitVariable](ds *DataStream[T], index int) T {
	v := ds.underlying[index]
	t := ds.toggles[index]
	ds.api.g.AssertIsEqual(t, 1)
	return v
}

// RangeUnderlying selects a range of the data stream. Performed on the underlying data directly.
func RangeUnderlying[T CircuitVariable](ds *DataStream[T], start, end int) *DataStream[T] {
	return newDataStream(ds.api, ds.underlying[start:end], ds.toggles[start:end])
}

// WindowUnderlying splits a DataStream into many equal sized List. Performed on the
// underlying data directly. Panics if `size` does not divide the length of the
// underlying list. Use Range to cut the list length into a multiple of `size`
// first
func WindowUnderlying[T CircuitVariable](ds *DataStream[T], size int, step ...int) *DataStream[List[T]] {
	l := len(ds.underlying)
	if len(step) > 1 {
		panic("invalid number of optional param 'step'")
	}
	stepSize := size
	if len(step) == 1 {
		stepSize = step[0]
	}
	if (l-size+stepSize)%stepSize != 0 {
		panic(fmt.Errorf("cannot window on DataStream of length %d window size %d step %d: uneven result windows", l, size, stepSize))
	}
	var toggles []frontend.Variable
	var ret []List[T]
	for i := 0; i <= l-size; i += stepSize {
		start := i
		end := start + size
		ret = append(ret, ds.underlying[start:end])
		var toggle frontend.Variable = 1
		for _, t := range ds.toggles[start:end] {
			toggle = ds.api.g.And(toggle, t)
		}
		toggles = append(toggles, toggle)
	}
	return newDataStream(ds.api, ret, toggles)
}

// AssertFunc returns 1 if the assertion passes, and 0 otherwise
type AssertFunc[T CircuitVariable] func(current T) Uint248

// AssertEach asserts on each valid element in the data stream
func AssertEach[T CircuitVariable](ds *DataStream[T], assertFunc AssertFunc[T]) {
	for i, data := range ds.underlying {
		pass := assertFunc(data).Val
		valid := ds.api.isEqual(ds.toggles[i], 1)
		pass = ds.api.g.Select(valid, pass, 1)
		ds.api.g.AssertIsEqual(pass, 1)
	}
}

// SortFunc returns 1 if a, b are sorted, 0 if not.
type SortFunc[T CircuitVariable] func(a, b T) Uint248

// IsSorted returns 1 if the data stream is sorted to the criteria of sortFunc, 0 if not.
func IsSorted[T CircuitVariable](ds *DataStream[T], sortFunc SortFunc[T]) Uint248 {
	// The following code uses prev and prevValid to pass the signal of last known
	// valid element of the data stream. This is needed because the stream could have
	// already been filtered, meaning we could have "gaps" between valid elements
	//
	//TODO:
	// we could use a bool in ds to indicate whether the toggles this ds has been
	// touched (the stream has been filtered) before this part of the user circuit
	// where this method is called. if it has not been touched, we probably don't
	// need to use prev and prevValid signals.
	api := ds.api.g
	var sorted frontend.Variable = 1
	prev := ds.underlying[0]
	prevValid := ds.toggles[0]

	for i := 1; i < len(ds.underlying); i++ {
		curr := ds.underlying[i]
		currValid := ds.toggles[i]

		newSorted := sortFunc(prev, curr).Val
		// if we found anything unsorted, then the rest of the sorted check is effectively useless
		useNewSorted := api.And(sorted, api.And(prevValid, currValid))
		sorted = api.Select(useNewSorted, newSorted, sorted)

		prev = Select(ds.api, newU248(currValid), curr, prev)
		prevValid = api.Select(currValid, currValid, prevValid)
	}
	return newU248(sorted)
}

// AssertSorted Performs the sortFunc on each valid pair of data points and asserts the result to be 1.
func AssertSorted[T CircuitVariable](ds *DataStream[T], sortFunc SortFunc[T]) {
	ds.api.Uint248.AssertIsEqual(IsSorted(ds, sortFunc), newU248(1))
}

// Count returns the number of valid elements (i.e. toggled on) in the data stream.
func Count[T CircuitVariable](ds *DataStream[T]) Uint248 {
	t := ds.toggles
	count := ds.api.g.Add(t[0], t[1], t[2:]...)
	return newU248(count)
}

type ZipMap2Func[T0, T1, R CircuitVariable] func(a T0, b T1) R

// ZipMap2 zips a data stream with a list and apply the map function over the
// zipped data. The underlying toggles of the result data stream depends on the
// toggles from the source data stream. Panics if the underlying data lengths
// mismatch
// Example: ZipMap2([1,2,3], [4,5,6], mySumFunc) -> [5,7,9]
func ZipMap2[T0, T1, R CircuitVariable](
	a *DataStream[T0], b List[T1],
	zipFunc ZipMap2Func[T0, T1, R],
) *DataStream[R] {
	if la, lb := len(a.underlying), len(b); la != lb {
		panic(fmt.Errorf("cannot zip: inconsistent underlying array lengths %d and %d", la, lb))
	}
	res := make([]R, len(a.underlying))
	for i := range a.underlying {
		va, vb := a.underlying[i], b[i]
		res[i] = zipFunc(va, vb)
	}
	return newDataStream(a.api, res, a.toggles)
}

type ZipMap3Func[T0, T1, T2, R CircuitVariable] func(a T0, b T1, c T2) R

// ZipMap3 zips a data stream with two other lists and apply the map function
// over the zipped data. The underlying toggles of the result data stream depends
// on the toggles from the source data stream.
// Example: ZipMap3([1,2,3], [4,5,6], [7,8,9], mySumFunc) -> [12,15,18]
func ZipMap3[T0, T1, T2, R CircuitVariable](
	a *DataStream[T0], b List[T1], c List[T2],
	zipFunc ZipMap3Func[T0, T1, T2, R],
) *DataStream[R] {
	if la, lb, lc := len(a.underlying), len(b), len(c); la != lb || la != lc {
		panic(fmt.Errorf("cannot zip: inconsistent underlying array lengths: %d, %d, %d", la, lb, lc))
	}
	res := make([]R, len(a.underlying))
	for i := range a.underlying {
		va, vb, vc := a.underlying[i], b[i], c[i]
		res[i] = zipFunc(va, vb, vc)
	}
	return newDataStream(a.api, res, a.toggles)
}

type GetValueFunc[T any] func(current T) Uint248

// GroupBy a given field (identified through the field func), call reducer on
// each group, and returns a data stream in which each element is an aggregation
// result of the group. The optional param maxUniqueGroupValuesOptional can be
// supplied to optimize performance. It assumes the worst case (all values in the
// data stream are unique) if no maxUniqueGroupValuesOptional is configured.
func GroupBy[T, R CircuitVariable](
	ds *DataStream[T],
	reducer ReduceFunc[T, R],
	reducerInit R,
	field GetValueFunc[T],
	maxUniqueGroupValuesOptional ...int,
) (*DataStream[R], error) {
	if len(maxUniqueGroupValuesOptional) > 1 {
		panic("invalid amount of optional params")
	}
	g := ds.api.g
	values := make([]frontend.Variable, len(ds.underlying))
	for i, v := range ds.underlying {
		values[i] = field(v).Val
	}
	groupValues, err := computeGroupValuesHint(g, values, ds.toggles)
	if err != nil {
		return nil, err
	}
	maxGroupValues := len(values)
	if len(maxUniqueGroupValuesOptional) == 1 {
		maxGroupValues = maxUniqueGroupValuesOptional[0]
	}
	aggResults := make([]R, maxGroupValues)
	aggResultToggles := make([]frontend.Variable, maxGroupValues)
	// Filter on each groupValue, then reduce using the user supplied function. Note
	// that the groupValues are computed using hints. This is ok because the
	// groupValues are used as predicates in the filter step. Assuming the
	// outside-of-circuit-computed groupValues are all malicious (does not exist in
	// the input data stream), then the filter step would result in empty data
	// streams, and the reduce results would be all toggled off. This decision is
	// made based on the premise of which it is accepted that we can't prove what's
	// NOT provided to the circuit as inputs.
	for i := 0; i < maxGroupValues; i++ {
		vs := groupValues[i]
		group := Filter(ds, func(current T) Uint248 {
			v := field(current)
			return newU248(g.IsZero(g.Sub(v.Val, vs)))
		})
		aggResults[i] = Reduce(group, reducerInit, reducer)
		// only turn on toggles for agg result if the filtered group has at least 1 item
		aggResultToggles[i] = g.Sub(1, g.IsZero(Count(group).Val))
	}
	return newDataStream(ds.api, aggResults, aggResultToggles), nil
}

func computeGroupValuesHint(api frontend.API, values, toggles []frontend.Variable) ([]frontend.Variable, error) {
	inputs := []frontend.Variable{len(values)}
	inputs = append(inputs, values...)
	inputs = append(inputs, toggles...)
	return api.Compiler().NewHint(GroupValuesHint, len(values), inputs...)
}

func GroupValuesHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	numValues := inputs[0].Int64()
	values := inputs[1 : 1+numValues]
	toggles := inputs[1+numValues:]

	var uniqueValues []*big.Int
	for i, v := range values {
		if toggles[i].Sign() == 0 {
			continue
		}
		found := false
		for _, uv := range uniqueValues {
			if uv.Cmp(v) == 0 {
				found = true
				break
			}
		}
		if !found {
			uniqueValues = append(uniqueValues, v)
		}
	}
	for i := len(uniqueValues); i < int(numValues); i++ {
		uniqueValues = append(uniqueValues, big.NewInt(0))
	}
	copy(outputs, uniqueValues)
	return nil
}

type MapFunc[T, R CircuitVariable] func(current T) R

// Map maps each valid element in the data stream by calling the user defined mapFunc
func Map[T, R CircuitVariable](ds *DataStream[T], mapFunc MapFunc[T, R]) *DataStream[R] {
	res := make([]R, len(ds.underlying))
	for i, data := range ds.underlying {
		res[i] = mapFunc(data)
	}
	return newDataStream(ds.api, res, ds.toggles)
}

type ReduceFunc[T, R CircuitVariable] func(accumulator R, current T) (newAccumulator R)

// Reduce reduces the data stream to another CircuitVariable with the given
// reducer and initial condition
func Reduce[T, R CircuitVariable](ds *DataStream[T], initial R, reducer ReduceFunc[T, R]) R {
	acc := initial
	for i, data := range ds.underlying {
		newAcc := reducer(acc, data)
		oldAccVals := acc.Values()
		values := make([]frontend.Variable, len(oldAccVals))
		for j, newAccV := range newAcc.Values() {
			values[j] = ds.api.g.Select(ds.toggles[i], newAccV, oldAccVals[j])
		}
		acc = acc.FromValues(values...).(R)
	}
	return acc
}

// FilterFunc must return 1/0 to include/exclude `current` in the filter result
type FilterFunc[T CircuitVariable] func(current T) Uint248

// Filter filters the data stream with the given predicate
func Filter[T CircuitVariable](ds *DataStream[T], predicate FilterFunc[T]) *DataStream[T] {
	api := ds.api.g
	newToggles := make([]frontend.Variable, len(ds.underlying))
	for i, data := range ds.underlying {
		toggle := predicate(data).Val
		valid := ds.api.isEqual(ds.toggles[i], 1)
		newToggles[i] = api.Select(api.And(toggle, valid), 1, 0)
	}
	return newDataStream(ds.api, ds.underlying, newToggles)
}

// MinGeneric finds out the minimum value from the data stream with the user
// defined sort function. Uses Reduce under the hood. Note if the data stream is
// empty (all data points are toggled off), this function returns MaxUint248.
func MinGeneric[T CircuitVariable](ds *DataStream[T], initialMin T, lt SortFunc[T]) T {
	return Reduce(ds, initialMin, func(min, current T) (newMin T) {
		curLtMin := lt(current, min)
		return Select(ds.api, curLtMin, current, min)
	})
}

// MaxGeneric finds out the maximum value from the data stream with the user
// defined sort function. Uses Reduce under the hood. Note if the data stream is
// empty (all data points are toggled off), this function returns 0.
func MaxGeneric[T CircuitVariable](ds *DataStream[T], initialMax T, gt SortFunc[T]) T {
	return Reduce(ds, initialMax, func(max, current T) (newMax T) {
		curGtMax := gt(current, max)
		return Select(ds.api, curGtMax, current, max)
	})
}

// Min finds out the minimum value from the data stream. Uses MinGeneric. Note if
// the data stream is empty (all data points are toggled off), this function
// returns MaxUint248.
func Min(ds *DataStream[Uint248]) Uint248 {
	return MinGeneric(ds, newU248(MaxUint248), ds.api.Uint248.IsLessThan)
}

// Max finds out the maximum value from the data stream. Uses MaxGeneric. Note if
// the data stream is empty (all data points are toggled off), this function
// returns 0.
func Max(ds *DataStream[Uint248]) Uint248 {
	return MaxGeneric(ds, newU248(0), ds.api.Uint248.IsGreaterThan)
}

// Sum sums values of the selected field in the data stream. Uses Reduce
func Sum(ds *DataStream[Uint248]) Uint248 {
	return Reduce(ds, newU248(0), func(sum Uint248, curr Uint248) (newSum Uint248) {
		return ds.api.Uint248.Add(sum, curr)
	})
}

// Mean calculates the arithmetic mean over the selected fields of the data stream. Uses Sum.
func Mean(ds *DataStream[Uint248]) Uint248 {
	sum := Sum(ds)
	quo, _ := ds.api.Uint248.Div(sum, Count(ds))
	return quo
}
