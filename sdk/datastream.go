package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
)

type DataStream[T CircuitVariable] struct {
	api        *CircuitAPI
	underlying []T
	toggles    []Variable
}

func NewDataStream[T CircuitVariable](api *CircuitAPI, in DataPoints[T]) *DataStream[T] {
	return &DataStream[T]{
		api:        api,
		underlying: in.Raw,
		toggles:    in.Toggles,
	}
}

func newDataStream[T CircuitVariable](api *CircuitAPI, in []T, toggles []Variable) *DataStream[T] {
	return &DataStream[T]{
		api:        api,
		underlying: in,
		toggles:    toggles,
	}
}

// GetUnderlying gets an element from the DataStream. Performed on the underlying data
// directly. It also requires the underlying data slot is valid
func GetUnderlying[T CircuitVariable](ds *DataStream[T], index int) T {
	v := ds.underlying[index]
	t := ds.toggles[index]
	AssertIsEqual(t, 1)
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
func WindowUnderlying[T CircuitVariable](ds *DataStream[T], size int) *DataStream[List[T]] {
	l := len(ds.underlying)
	if l%size != 0 {
		panic(fmt.Errorf("cannot Window on DataStream of size %d: %d % %d != 0", l, l, size))
	}
	var toggles []Variable
	var ret []List[T]
	for i := 0; i < l-size; i += size {
		start := i
		end := start + size
		ret = append(ret, ds.underlying[start:end])
		toggle := newV(0)
		for _, t := range ds.toggles[start:end] {
			toggle = And(ds.api, toggle, t)
		}
		toggles = append(toggles, toggle)
	}
	return newDataStream(ds.api, ret, toggles)
}

type MapFunc[T any] func(current T) Variable

type AssertFunc[T CircuitVariable] func(current T) Variable

func AssertEach[T CircuitVariable](ds *DataStream[T], assertFunc AssertFunc[T]) {
	for i, data := range ds.underlying {
		pass := assertFunc(data)
		valid := Equal(ds.api, ds.toggles[i], newV(1))
		pass = Select(ds.api, valid, pass, newV(1))
		AssertIsEqual(ds.api, pass, newV(1))
	}
}

// SortFunc returns 1 if a, b are sorted, 0 if not.
type SortFunc[T CircuitVariable] func(a, b T) Variable

// IsSorted returns 1 if the data stream is sorted to the criteria of sortFunc, 0 if not.
func IsSorted[T CircuitVariable](ds *DataStream[T], sortFunc SortFunc[T]) Variable {
	// The following code uses prev and prevValid to pass the signal of last known
	// valid element of the data stream. This is needed because the stream could have
	// already been filtered, meaning we could have "gaps" between valid elements
	//
	//TODO:
	// we could use a bool in ds to indicate whether the toggles this ds has been
	// touched (the stream has been filtered) before this part of the user circuit
	// where this method is called. if it has not been touched, we probably don't
	// need to use prev and prevValid signals.
	api := ds.api
	var sorted Variable
	prev := ds.underlying[0]
	prevValid := ds.toggles[0]

	for i := 1; i < len(ds.underlying); i++ {
		curr := ds.underlying[i]
		currValid := ds.toggles[i]

		sorted = sortFunc(prev, curr)
		sorted = Select(api, And(api, prevValid, currValid), sorted, newV(1))

		prev = Select(api, currValid, curr, prev)
		prevValid = currValid
	}
	return sorted
}

// AssertSorted Performs the sortFunc on each valid pair of data points and assert the result to be 1.
func AssertSorted[T CircuitVariable](ds *DataStream[T], sortFunc SortFunc[T]) {
	AssertIsEqual(ds.api, IsSorted(ds, sortFunc), newV(1))
}

// Count returns the number of valid elements (i.e. toggled on) in the data stream.
func Count[T CircuitVariable](ds *DataStream[T]) Variable {
	t := ds.toggles
	count := Add(ds.api, t[0], t[1], t[2:]...) // Todo: cache this signal in case it's used more than once
	return count
}

func GroupBy[T, R CircuitVariable](ds *DataStream[T], f ReduceFunc[T, R], aggInitial R, groupValues []Variable, byFieldIndex int) *DataStream[R] {
	aggResults := make([]R, len(groupValues))
	aggResultToggles := make([]Variable, len(aggResults))
	for i, p := range groupValues {
		group := Filter(ds, func(current T) Variable {
			v := current.Values()[byFieldIndex]
			return Equal(ds.api, newV(v), p)
		})
		aggResults[i] = Reduce(group, aggInitial, f)
		aggResultToggles[i] = Sub(ds.api, newV(1), IsZero(ds.api, p))
	}
	return newDataStream(ds.api, aggResults, aggResultToggles)
}

type MapGenericFunc[T, R CircuitVariable] func(current T) R

func Map[T, R CircuitVariable](ds *DataStream[T], mapFunc MapGenericFunc[T, R]) *DataStream[R] {
	res := make([]R, len(ds.underlying))
	for i, data := range ds.underlying {
		res[i] = mapFunc(data)
	}
	return newDataStream(ds.api, res, ds.toggles)
}

type ReduceFunc[T, R CircuitVariable] func(accumulator R, current T) (newAccumulator R)

// Reduce reduces the data stream to another CircuitVariable
func Reduce[T, R CircuitVariable](ds *DataStream[T], initial R, reduceFunc ReduceFunc[T, R]) R {
	var acc = initial
	for i, data := range ds.underlying {
		newAcc := reduceFunc(acc, data)
		oldAccVals := acc.Values()
		values := make([]frontend.Variable, len(oldAccVals))
		for j, newAccV := range newAcc.Values() {
			values[j] = Select(ds.api, ds.toggles[i], newV(newAccV), newV(oldAccVals[j]))
		}
		acc.SetValues(values...)
	}
	return acc
}

type FilterGenericFunc[T CircuitVariable] func(current T) Variable

func Filter[T CircuitVariable](ds *DataStream[T], filterFunc FilterGenericFunc[T]) *DataStream[T] {
	newToggles := make([]Variable, len(ds.underlying))
	for i, data := range ds.underlying {
		toggle := filterFunc(data)
		valid := Equal(ds.api, ds.toggles[i], newV(1))
		newToggles[i] = Select(ds.api, And(ds.api, toggle, valid), newV(1), newV(0))
	}
	return newDataStream(ds.api, ds.underlying, newToggles)
}

type Reduce2Func[T any] func(accumulator [2]Variable, current T) (newAccumulator [2]Variable)

// FilterFunc must return 1/0 to include/exclude `current` in the filter result
type FilterFunc[T any] func(current T) Variable

type GetValueFunc[T any] func(current T) Variable

// Min finds out the minimum value of the selected field from the data stream. Uses Reduce under the hood.
func Min(ds *DataStream[Variable], getValue GetValueFunc[Variable]) Variable {
	return Reduce(ds, newV(MaxInt), func(min Variable, current Variable) (newMin Variable) {
		curr := getValue(current)
		curLtMin := LT(ds.api, curr, min)
		return Select(ds.api, curLtMin, curr, min)
	})
}

// Max finds out the maximum value of the selected field from the data stream. Uses Reduce under the hood.
func Max(ds *DataStream[Variable]) Variable {
	return Reduce(ds, newV(0), func(max Variable, curr Variable) (newMax Variable) {
		curGtMax := GT(ds.api, curr, max)
		return Select(ds.api, curGtMax, curr, max)
	})
}

// Sum sums values of the selected field in the data stream. Uses Reduce.
func Sum(ds *DataStream[Variable]) Variable {
	return Reduce(ds, newV(0), func(sum Variable, curr Variable) (newSum Variable) {
		return Add(ds.api, sum, curr)
	})
}

// Mean calculates the arithmetic mean over the selected fields of the data stream. Uses Sum.
// Note that
func Mean(ds *DataStream[Variable]) Variable {
	sum := Sum(ds)
	quo, _ := ds.api.QuoRem(sum, Count(ds))
	return quo
}
