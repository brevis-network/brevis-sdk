package sdk

import (
	"bytes"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"

	"github.com/consensys/gnark-crypto/ecc"
)

// returns little endian bits of data.
// negative value are not accepted.
// if data is negative value the circuit's behavior may not match the expected outcome.
func decomposeBits(data *big.Int, length uint) []uint {
	return decompose[uint](data, 1, length)
}

func recompose[T uint | byte](data []T, bitSize int) *big.Int {
	d := make([]*big.Int, len(data))
	for i := 0; i < len(data); i++ {
		d[i] = big.NewInt(int64(data[i]))
	}
	return recomposeBig(d, bitSize)
}

func recomposeBig(data []*big.Int, bitSize int) *big.Int {
	r := big.NewInt(0)
	for i := 0; i < len(data); i++ {
		r.Add(r, new(big.Int).Lsh(data[i], uint(i*bitSize)))
		r.Mod(r, ecc.BN254.ScalarField())
	}
	return r
}

func decompose[T uint | byte](data *big.Int, bitSize uint, length uint) []T {
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

	res := decomposeBig(data, bitSize, length)
	ret := make([]T, length)
	for i, limb := range res {
		ret[i] = T(limb.Uint64())
	}
	return ret
}

func decomposeAndSlice(data *big.Int, bitSize, length uint) []*big.Int {
	decomposed := make([]*big.Int, length)
	base := new(big.Int).Lsh(big.NewInt(1), bitSize)
	d := new(big.Int).Set(data)

	if d.Sign() < 0 {
		panic(fmt.Errorf("negative values are not supported: %s", d.String()))
	}

	for i := 0; i < int(length); i++ {
		rem := new(big.Int)
		d.DivMod(d, base, rem)
		decomposed[i] = rem
	}
	return decomposed
}

func decomposeBig(data *big.Int, bitSize, length uint) []*big.Int {
	if uint(data.BitLen()) > length*bitSize {
		panic(fmt.Errorf("decomposed integer (bit len %d) does not fit into output (bit len %d, length %d)",
			data.BitLen(), bitSize, length))
	}
	return decomposeAndSlice(data, bitSize, length)
}

func decomposeBitsExactOfAbs(data *big.Int) []uint {
	abs := new(big.Int).Abs(data)
	var ret []uint
	for abs.Sign() > 0 {
		bit := new(big.Int)
		abs.DivMod(abs, big.NewInt(2), bit)
		ret = append(ret, uint(bit.Uint64()))
	}
	return ret
}

func PackBitsToInt(bits []uint, bitSize int) []*big.Int {
	return packBitsToInt(bits, bitSize)
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

func newVars[T any](vs []T) []frontend.Variable {
	ret := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		ret[i] = v
	}
	return ret
}

// copied from
// https://github.com/Consensys/gnark/blob/5711c4ae475535ce2a0febdeade86ff98914a378/internal/utils/convert.go#L39C1-L39C1
// with minor changes
func fromInterface(input interface{}) *big.Int {
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
	case bool:
		var b uint64
		if v {
			b = 1
		}
		r.SetUint64(b)
	case string:
		if _, ok := r.SetString(v, 0); !ok {
			panic("unable to set big.Int from string " + v)
		}
	case common.Address:
		r.SetBytes(v[:])
	case []byte:
		r.SetBytes(v)
	default:
		panic("unsupported type for conversion to *big.Int: " + fmt.Sprintf("%T", input))
	}
	return &r
}

// Inspired by https://github.com/Consensys/gnark/blob/429616e33c97ed21113dd87787c043e8fb43720c/frontend/cs/scs/api.go#L523
// To reduce constraints comsumption, use predefined number of variable's bits.
// func Cmp(api frontend.API, i1, i2 frontend.Variable, nbBits int) frontend.Variable {
// 	bi1 := bits.ToBinary(api, i1, bits.WithNbDigits(nbBits))
// 	bi2 := bits.ToBinary(api, i2, bits.WithNbDigits(nbBits))

// 	var res frontend.Variable
// 	res = 0

// 	for i := nbBits - 1; i >= 0; i-- {
// 		iszeroi1 := api.IsZero(bi1[i])
// 		iszeroi2 := api.IsZero(bi2[i])

// 		i1i2 := api.And(bi1[i], iszeroi2)
// 		i2i1 := api.And(bi2[i], iszeroi1)

// 		n := api.Select(i2i1, -1, 0)
// 		m := api.Select(i1i2, 1, n)

// 		res = api.Select(api.IsZero(res), m, res)
// 	}
// 	return res
// }

// Cmp compares i1 and i2 based on a specified number of bits (nbBits).
// Returns -1 if i1 < i2, 0 if i1 == i2, and 1 if i1 > i2.
// This version is optimized to avoid full bit decomposition and only uses range checking and hinting.
func Cmp(api frontend.API, i1, i2 frontend.Variable, nbBits int) frontend.Variable {
	if nbBits > api.Compiler().Field().BitLen()-2 {
		panic("Cmp called with nbBits too large.")
	}

	rangeChecker := rangecheck.New(api)
	rangeChecker.Check(i1, nbBits)
	rangeChecker.Check(i2, nbBits)

	results, err := api.Compiler().NewHint(CmpHint, 1, i1, i2)
	if err != nil {
		panic(err)
	}
	result := results[0]

	// Ensure the result is -1, 0, or 1
	resultSquared := api.Mul(result, result)
	api.AssertIsBoolean(resultSquared)

	// Compute if i1 < i2 based on the hint (result == -1)
	first_smaller := api.IsZero(api.Add(result, 1))

	// Select the bigger and smaller of i1 and i2
	bigger := api.Select(first_smaller, i2, i1)
	smaller := api.Select(first_smaller, i1, i2)

	// Check the difference to ensure the hint was correct
	diff := api.Sub(bigger, smaller)
	rangeChecker.Check(diff, nbBits)

	// Handle the equality case: i1 == i2
	equal := api.IsZero(diff)
	result_zero := api.IsZero(result)
	api.AssertIsEqual(api.Xor(equal, result_zero), 0)

	return result
}

// CmpHint is a hint function that compares two values and returns -1, 0, or 1
func CmpHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// Set result based on comparison: -1 if inputs[0] < inputs[1], 0 if equal, 1 if greater
	results[0].SetInt64(int64(inputs[0].Cmp(inputs[1])))
	return nil
}

func mustWriteToBytes(w io.WriterTo) []byte {
	b := bytes.NewBuffer([]byte{})
	_, err := w.WriteTo(b)
	if err != nil {
		panic(fmt.Errorf("failed to write vk to bytes stream %s", err.Error()))
	}
	return b.Bytes()
}

func parseBitStr(s string) []frontend.Variable {
	ret := make([]frontend.Variable, len(s))
	for i, c := range s {
		if c == '0' {
			ret[i] = 0
		} else {
			ret[i] = 1
		}
	}
	return ret
}

func twosComplement(bits []uint, n int) []uint {

	if len(bits) >= n && !isValidEdgeCase(bits, n) {
		panic(fmt.Errorf("invalid input: bit length %d exceeds n-1 bits", len(bits)))
	}

	padded := padBitsRight(bits, n, 0)
	flipped := flipBits(padded)
	a := recompose(flipped, 1)
	a.Add(a, big.NewInt(1))
	d := decomposeAndSlice(a, 1, uint(n))
	ret := make([]uint, len(d))
	for i, b := range d {
		ret[i] = uint(b.Uint64())
	}
	return ret
}

func isValidEdgeCase(bits []uint, n int) bool {
	if len(bits) != n {
		return false
	}
	// Check if the input is [0, ..., 0, 1].
	for i := 0; i < n-1; i++ {
		if bits[i] != 0 {
			return false
		}
	}
	return bits[n-1] == 1
}

func flipBits(bits []uint) []uint {
	flipped := make([]uint, len(bits))
	for j := 0; j < len(bits); j++ {
		flipped[j] = ^bits[j] & 1
	}
	return flipped
}

func padBitsRight(bits []uint, n int, with uint) []uint {
	if len(bits) > n {
		panic(fmt.Errorf("invalid input: length of bits %d exceeds padding length %d", len(bits), n))
	}
	ret := make([]uint, n)
	copy(ret, bits)
	for i := len(bits); i < n; i++ {
		ret[i] = with
	}
	return ret
}

func ensureNotCircuitVariable(v any) {
	if _, ok := v.(CircuitVariable); ok {
		panic(fmt.Errorf("cannot initialize constant circuit variable with circuit variable type %T", v))
	}
}

func dbgPrint(condition bool, format string, args ...interface{}) {
	if condition {
		fmt.Printf(format, args...)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func CheckNumberPowerOfTwo(n int) bool {
	return n&(n-1) == 0
}

type ProofWriter struct {
	Keys   [][]byte
	Values [][]byte
}

func (p *ProofWriter) Put(key []byte, value []byte) error {
	p.Keys = append(p.Keys, key)
	p.Values = append(p.Values, value)
	return nil
}

func (p *ProofWriter) Delete(key []byte) error {
	return nil
}

func getTransactionProof(bk *types.Block, index int) (nodes [][]byte, keyIndex, leafRlpPrefix []byte, err error) {
	var indexBuf []byte
	keyIndex = rlp.AppendUint64(indexBuf[:0], uint64(index))

	db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	tt := trie.NewEmpty(db)

	txRootHash := types.DeriveSha(bk.Transactions(), tt)
	if txRootHash != bk.TxHash() {
		err = fmt.Errorf("tx root hash mismatch, blk: %d, index: %d, tx root hash: %x != %x", bk.NumberU64(), index, txRootHash, bk.TxHash())
		return
	}

	proofWriter := &ProofWriter{
		Keys:   [][]byte{},
		Values: [][]byte{},
	}
	err = tt.Prove(keyIndex, proofWriter)
	if err != nil {
		return
	}
	var leafRlp [][]byte
	leafValue := proofWriter.Values[len(proofWriter.Values)-1]
	err = rlp.DecodeBytes(leafValue, &leafRlp)
	if err != nil {
		return
	}
	if len(leafRlp) != 2 {
		err = fmt.Errorf("invalid leaf rlp len:%d, index:%d, bk:%s", len(leafRlp), index, bk.Number().String())
		return
	}
	return proofWriter.Values, keyIndex, leafValue[:len(leafValue)-len(leafRlp[1])], nil
}
