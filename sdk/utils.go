package sdk

import (
	"bytes"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// returns little endian bits of data
func decomposeBits(data *big.Int, length int) []uint {
	return decompose[uint](data, 1, length)
}

func recompose[T uint | byte](data []T, bitSize int) *big.Int {
	r := big.NewInt(0)
	for i := 0; i < len(data); i++ {
		d := big.NewInt(int64(data[i]))
		r.Add(r, new(big.Int).Lsh(d, uint(i*bitSize)))
		r.Mod(r, ecc.BLS12_377.ScalarField())
	}
	return r
}

func decompose[T uint | byte](data *big.Int, bitSize uint, length int) []T {
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

func packBitsToInt(bits []uint, bitSize int) []*big.Int {
	var r []*big.Int
	for i := 0; i < len(bits); i += bitSize {
		end := i + bitSize
		if end > len(bits) {
			end = len(bits)
		}
		bs := bits[i:end]
		z := recompose(bs, 1)
		r = append(r, z)
	}
	return r
}

// flips the order of the groups of groupSize. e.g. [1,2,3,4,5,6] with groupSize 2 is flipped to [5,6,3,4,1,2]
func flipByGroups[T any](in []T, groupSize int) []T {
	res := make([]T, len(in))
	copy(res, in)
	for i := 0; i < len(res)/groupSize/2; i++ {
		for j := 0; j < groupSize; j++ {
			a := i*groupSize + j
			b := len(res) - (i+1)*groupSize + j
			res[a], res[b] = res[b], res[a]
		}
	}
	return res
}

// copied from
// https://github.com/Consensys/gnark/blob/5711c4ae475535ce2a0febdeade86ff98914a378/internal/utils/convert.go#L39C1-L39C1
// with minor changes
func var2BigInt(input interface{}) *big.Int {
	if input == nil {
		return big.NewInt(0)
	}
	in := input.(interface{})
	var r big.Int
	switch v := in.(type) {
	case Variable:
		r.Set(var2BigInt(v.Val))
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

func mustWriteToBytes(w io.WriterTo) []byte {
	bytes := bytes.NewBuffer([]byte{})
	_, err := w.WriteTo(bytes)
	if err != nil {
		panic(fmt.Errorf("failed to write vk to bytes stream %s", err.Error()))
	}
	return bytes.Bytes()
}
