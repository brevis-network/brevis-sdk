package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

type DataStream[T CircuitVariable] struct {
	api        *CircuitAPI
	underlying []T
	toggles    []Variable
	max        int
}

func NewDataStream[T CircuitVariable](api *CircuitAPI, in DataPoints[T]) *DataStream[T] {
	return &DataStream[T]{
		api:        api,
		underlying: in.Raw,
		toggles:    in.Toggles,
		max:        NumMaxDataPoints, // TODO allow developer to customize max
	}
}

func newDataStream[T CircuitVariable](api *CircuitAPI, in []T, toggles []Variable, max int) *DataStream[T] {
	return &DataStream[T]{
		api:        api,
		underlying: in,
		toggles:    toggles,
		max:        max,
	}
}

// Get gets an element from the data stream. Performed on the underlying data
// directly. It also requires the underlying data slot is valid
func (ds *DataStream[T]) Get(index int) T {
	v := ds.underlying[index]
	t := ds.toggles[index]
	ds.api.AssertIsEqual(t, 1)
	return v
}

// Range selects a range of the data stream. Performed on the underlying data directly.
func (ds *DataStream[T]) Range(start, end int) *DataStream[T] {
	return newDataStream(ds.api, ds.underlying[start:end], ds.toggles[start:end], end-start)
}

type MapFunc[T any] func(current T) Variable

// Map calls the input mapFunc on every valid element in the stream
func (ds *DataStream[T]) Map(mapFunc MapFunc[T]) *DataStream[Variable] {
	res := make([]Variable, ds.max)
	for i, data := range ds.underlying {
		res[i] = mapFunc(data)
	}
	return newDataStream(ds.api, res, ds.toggles, ds.max)
}

type Map2Func[T CircuitVariable] func(current T) Tuple[T]

// Map2 is like Map but maps every element to two variables
func (ds *DataStream[T]) Map2(mapFunc Map2Func[T]) *DataStream[Tuple[T]] {
	var mapFunc2 MapGenericFunc[T, Tuple[T]] = mapFunc
	return Map(ds, mapFunc)
}

type AssertFunc[T CircuitVariable] func(current T) Variable

func AssertEach[T CircuitVariable](ds *DataStream[T], assertFunc AssertFunc[T]) {
	for i, data := range ds.underlying {
		pass := assertFunc(data)
		valid := Equal(ds.api, ds.toggles[i], newVariable(1))
		pass = Select(ds.api, valid, pass, newVariable(1))
		AssertIsEqual(ds.api, pass, newVariable(1))
	}
}

func AssertIsEqual(api *CircuitAPI, a, b CircuitVariable) {
	aVals := a.Values()
	bVals := b.Values()
	if len(aVals) != len(bVals) {
		panic("AssertIsEqual inconsistent values len")
	}
	for i := range aVals {
		api.AssertIsEqual(aVals[i], bVals[i])
	}
}

// SortFunc returns 1 if a, b are sorted, 0 if not.
type SortFunc func(a, b Variable) Variable

// IsSorted returns 1 if the data stream is sorted to the criteria of sortFunc, 0 if not.
func (ds *DataStream[T]) IsSorted(getValue GetValueFunc[T], sortFunc SortFunc) Variable {
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
	prev := getValue(ds.underlying[0])
	prevValid := ds.toggles[0]

	for i := 1; i < ds.max; i++ {
		curr := getValue(ds.underlying[i])
		currValid := ds.toggles[i]

		sorted = sortFunc(prev, curr)
		sorted = api.API.Select(api.API.And(prevValid, currValid), sorted, 1)

		prev = api.Select(currValid, curr, prev)
		prevValid = currValid
	}
	return sorted
}

// AssertSorted Performs the sortFunc on each valid pair of data points and assert the result to be 1.
func (ds *DataStream[T]) AssertSorted(getValue GetValueFunc[T], sortFunc SortFunc) {
	ds.api.AssertIsEqual(ds.IsSorted(getValue, sortFunc), 1)
}

// Count returns the number of valid elements (i.e. toggled on) in the data stream.
func (ds *DataStream[T]) Count() Variable {
	t := ds.toggles
	count := ds.api.API.Add(t[0], t[1], t[2:]...) // Todo: cache this signal in case it's used more than once
	return count
}

type ReduceFunc[T CircuitVariable] func(accumulator Variable, current T) (newAccumulator Variable)

// Reduce reduces the data stream to a single circuit variable
func (ds *DataStream[T]) Reduce(initial *Variable, reduceFunc ReduceGenericFunc[T, *Variable]) *Variable {
	return Reduce(ds, initial, reduceFunc)
}

type MapGenericFunc[T, R CircuitVariable] func(current T) R

func Map[T, R CircuitVariable](ds *DataStream[T], mapFunc MapGenericFunc[T, R]) *DataStream[R] {
	res := make([]R, ds.max)
	for i, data := range ds.underlying {
		res[i] = mapFunc(data)
	}
	return newDataStream(ds.api, res, ds.toggles, ds.max)
}

type ReduceGenericFunc[T, R CircuitVariable] func(accumulator R, current T) (newAccumulator R)

func Reduce[T, R CircuitVariable](ds *DataStream[T], initial R, reduceFunc ReduceGenericFunc[T, R]) R {
	var acc = initial
	for i, data := range ds.underlying {
		newAcc := reduceFunc(acc, data)
		oldAccVals := acc.Values()
		values := make([]frontend.Variable, len(oldAccVals))
		for j, newAccV := range newAcc.Values() {
			values[j] = ds.api.Select(ds.toggles[i], newAccV, oldAccVals[j])
		}
		acc.SetValues(values...)
	}
	return acc
}

func Partition[T CircuitVariable](ds *DataStream[T], n int) *DataStream[Tuple[T]] {
	l := len(ds.underlying)
	var ret []Tuple[T]
	for i := 0; i < l-n; i += n {
		start := i
		end := start + n
		if end > l {
			end = l
		}
		ret = append(ret, ds.underlying[start:end])
	}
	return newDataStream(ds.api, ret, ds.toggles, ds.max)
}

type FilterGenericFunc[T CircuitVariable] func(current T) Variable

func Filter[T CircuitVariable](ds *DataStream[T], filterFunc FilterGenericFunc[T]) *DataStream[T] {
	newToggles := make([]Variable, ds.max)
	for i, data := range ds.underlying {
		toggle := filterFunc(data)
		valid := Equal(ds.api, ds.toggles[i], newVariable(1))
		newToggles[i] = Select(ds.api, ds.api.And(toggle, valid), newVariable(1), newVariable(0))
	}
	return newDataStream(ds.api, ds.underlying, newToggles, ds.max)
}

type Reduce2Func[T any] func(accumulator [2]Variable, current T) (newAccumulator [2]Variable)

// FilterFunc must return 1/0 to include/exclude `current` in the filter result
type FilterFunc[T any] func(current T) Variable

type GetValueFunc[T any] func(current T) Variable

// Min finds out the minimum value of the selected field from the data stream. Uses Reduce under the hood.
func Min(ds *DataStream[T], getValue GetValueFunc[T]) Variable {
	maxInt := new(big.Int).Sub(ecc.BLS12_377.ScalarField(), big.NewInt(1))
	return ds.Reduce(maxInt, func(min Variable, current T) (newMin Variable) {
		curr := getValue(current)
		curLtMin := ds.api.LT(curr, min)
		return ds.api.Select(curLtMin, curr, min)
	})
}

// Max finds out the maximum value of the selected field from the data stream. Uses Reduce under the hood.
func (ds *DataStream[T]) Max(getValue GetValueFunc[T]) Variable {
	return ds.Reduce(0, func(max Variable, current T) (newMax Variable) {
		curr := getValue(current)
		curGtMax := ds.api.GT(curr, max)
		return ds.api.Select(curGtMax, curr, max)
	})
}

// Sum sums values of the selected field in the data stream. Uses Reduce.
func (ds *DataStream[T]) Sum(getValue GetValueFunc[T]) Variable {
	return ds.Reduce(0, func(sum Variable, current T) (newSum Variable) {
		curr := getValue(current)
		return ds.api.Add(sum, curr)
	})
}

// Mean calculates the arithmetic mean over the selected fields of the data stream. Uses Sum.
func (ds *DataStream[T]) Mean(getValue GetValueFunc[T]) Variable {
	sum := ds.Sum(getValue)
	return ds.api.Div(sum, ds.Count())
}

// StdDev calculates the standard deviation over the selected fields of the data stream. Uses Mean and Sum.
// Uses the formula: 𝛔 = sqrt(Σ(x_i - μ)^2 / N)
func (ds *DataStream[T]) StdDev(getValue GetValueFunc[T]) Variable {
	mu := ds.Mean(getValue)
	n := ds.Count()

	// compute k = Σ(x_i - μ)^2
	k := ds.Reduce(0, func(acc Variable, current T) Variable {
		x := getValue(current)
		r := ds.api.Sub(x, mu)
		r2 := ds.api.Mul(r, r)
		return ds.api.Add(acc, r2)
	})

	return ds.api.Sqrt(ds.api.Div(k, n))
}

func (ds *DataStream[T]) Partition(n int) *DataStream[Tuple[T]] {
	l := len(ds.underlying)
	var ret []Tuple[T]
	for i := 0; i < l-n; i += n {
		start := i
		end := start + n
		if end > l {
			end = l
		}
		ret = append(ret, ds.underlying[start:end])
	}
	return newDataStream(ds.api, ret, ds.toggles, ds.max)
}
