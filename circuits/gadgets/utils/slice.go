package utils

import (
	"github.com/consensys/gnark/frontend"
)

func Flip[T any](in []T) []T {
	res := make([]T, len(in))
	copy(res, in)
	for i := 0; i < len(in)/2; i++ {
		tmp := res[i]
		res[i] = res[len(res)-1-i]
		res[len(res)-1-i] = tmp
	}
	return res
}

func FlipSubSlice[T any](arr []T, chunkSize int) []T {
	if len(arr)%chunkSize != 0 {
		panic("invalid length")
	}
	ret := []T{}
	for i := 0; i < len(arr); i += chunkSize {
		ret = append(ret, Flip(arr[i:i+chunkSize])...)
	}
	return ret
}

func FlipKeccakFvBits(api frontend.API, d frontend.Variable, decomposedBitLen int) []frontend.Variable {
	arr := api.ToBinary(d, decomposedBitLen)
	bits := Flip(arr)
	if len(arr)%8 != 0 {
		panic("invalid length")
	}
	return FlipSubSlice(bits, 8)
}

func Slice2FVs[T any](a []T) []frontend.Variable {
	vars := []frontend.Variable{}
	for _, v := range a {
		vars = append(vars, v)
	}
	return vars
}
