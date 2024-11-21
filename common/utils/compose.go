package utils

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// DecomposeBits returns little endian bits of data
func DecomposeBits(data *big.Int, length int) []uint {
	return decompose[uint](data, 1, length)
}

func recompose[T uint | byte](data []T, bitSize int) *big.Int {
	r := big.NewInt(0)
	for i := 0; i < len(data); i++ {
		d := big.NewInt(int64(data[i]))
		r.Add(r, new(big.Int).Lsh(d, uint(i*bitSize)))
		r.Mod(r, ecc.BN254.ScalarField())
	}
	return r
}

func decompose[T uint | byte](data *big.Int, bitSize uint, length int) []T {
	var maxBitSize uint
	switch any(*new(T)).(type) {
	case uint:
		maxBitSize = 64
	case byte:
		maxBitSize = 8
	}
	if bitSize > maxBitSize {
		panic(fmt.Errorf("bitSize %d exceeds the bit capacity of type %T", bitSize, *new(T)))
	}
	if data.Sign() < 0 {
		panic(fmt.Errorf("negative values are not supported: %s", data.String()))
	}
	if data.BitLen() > length*int(bitSize) {
		panic(fmt.Errorf("decomposed integer (bit len %d) does not fit into output (bit len %d, length %d)",
			data.BitLen(), bitSize, length))
	}
	decomposed := make([]T, length)
	base := new(big.Int).Lsh(big.NewInt(1), bitSize)
	d := new(big.Int).Set(data)
	for i := 0; i < length; i++ {
		rem := new(big.Int)
		d.DivMod(d, base, rem)
		decomposed[i] = T(rem.Uint64())
	}
	return decomposed
}

func PackBitsToInt(bits []uint) []*big.Int {
	bitLen := ecc.BN254.ScalarField().BitLen() - 1
	var r []*big.Int
	for i := 0; i < len(bits); i += bitLen {
		end := i + bitLen
		if end > len(bits) {
			end = len(bits)
		}
		bs := bits[i:end]
		z := recompose(bs, 1)
		r = append(r, z)
	}
	return r
}

// copied from
// https://github.com/Consensys/gnark/blob/5711c4ae475535ce2a0febdeade86ff98914a378/internal/utils/convert.go#L39C1-L39C1
// with minor changes
func Var2BigInt(input interface{}) *big.Int {
	if input == nil {
		return big.NewInt(0)
	}
	var r big.Int
	switch v := input.(type) {
	case big.Int:
		r.Set(&v)
	case *big.Int:
		r.Set(v)
	case uint8:
		r.SetUint64(uint64(v))
	case uint16:
		r.SetUint64(uint64(v))
	case uint32:
		r.SetUint64(uint64(v))
	case uint64:
		r.SetUint64(v)
	case uint:
		r.SetUint64(uint64(v))
	case int8:
		r.SetInt64(int64(v))
	case int16:
		r.SetInt64(int64(v))
	case int32:
		r.SetInt64(int64(v))
	case int64:
		r.SetInt64(v)
	case int:
		r.SetInt64(int64(v))
	case string:
		if _, ok := r.SetString(v, 0); !ok {
			panic("unable to set big.Int from string " + v)
		}
	case []byte:
		r.SetBytes(v)
	}
	return &r
}

func Byte32ToFrBits(b32 [2]*big.Int, frSize int) []uint {
	var bits []uint
	bits = append(bits, DecomposeBits(Var2BigInt(b32[0]), frSize)...)
	bits = append(bits, DecomposeBits(Var2BigInt(b32[1]), 32*8-frSize)...)
	return bits
}

// ParseBytes32 decomposes data (big endian) into little endian bits then recomposes the
// result into two big ints in the form of {lo, hi}
func ParseBytes32(data []byte, frSize int) [2]*big.Int {
	if len(data) > 32 {
		panic(fmt.Errorf("ParseBytes32 called with data of length %d", len(data)))
	}

	// 256
	bits := DecomposeBits(new(big.Int).SetBytes(data), 256)

	lo := recompose(bits[:frSize], 1)
	hi := recompose(bits[frSize:], 1)

	return [2]*big.Int{lo, hi}
}

// func ParseBytes322(data []byte) Bytes32 {
// 	if len(data) > 32 {
// 		panic(fmt.Errorf("ParseBytes32 called with data of length %d", len(data)))
// 	}

// 	bits := decomposeBits(new(big.Int).SetBytes(data), 256)

// 	lo := recompose(bits[:numBitsPerVar], 1)
// 	hi := recompose(bits[numBitsPerVar:], 1)

// 	return Bytes32{[2]frontend.Variable{lo, hi}}
// }
