package rlp

import (
	"github.com/celer-network/brevis-sdk/gadgets/keccak"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
)

type KeccakOrLiteralHex struct {
	Output       [64]frontend.Variable
	OutputLength frontend.Variable
}

func Multiplexer(
	api frontend.API,
	selector frontend.Variable,
	wIn int,
	nIn int,
	input [][]frontend.Variable,
) (output []frontend.Variable) {

	decoder, outputSuccess := Decoder(api, nIn, selector)
	for i := 0; i < wIn; i++ {
		ep := EscalarProduct(api, nIn, input[i], decoder)
		output = append(output, ep)
	}

	api.AssertIsEqual(outputSuccess, 1)
	return
}

func Decoder(api frontend.API, width int, input frontend.Variable) (output []frontend.Variable, outputSuccess frontend.Variable) {
	outputSuccess = 0
	for i := 0; i < width; i++ {
		value := Equal(api, i, input)
		output = append(output, value)
		outputSuccess = api.Add(outputSuccess, value)
	}
	api.AssertIsBoolean(outputSuccess)
	return
}

func EscalarProduct(api frontend.API, width int, inputA []frontend.Variable, inputB []frontend.Variable) (output frontend.Variable) {
	output = 0
	for i := 0; i < width; i++ {
		output = api.Add(output, api.Mul(inputA[i], inputB[i]))
	}
	return
}

func Keccak256AsNibbles(
	api frontend.API,
	inLen frontend.Variable, // if input is a padded rlp data, the inlen is the decoded rlp length without padding part
	blocks [keccak.MAX_ROUNDS][17]frontend.Variable,
	roundIndex frontend.Variable,
) *KeccakOrLiteralHex {

	var h = keccak.Keccak256(api, blocks, roundIndex)

	// 64 nibble
	var nibbles [64]frontend.Variable
	for i, r := range h {
		rBits := api.ToBinary(r, 64)

		for j := 0; j < 16; j++ {
			nibbles[i*16+j] = api.FromBinary(rBits[j*4 : (j+1)*4]...)
		}
	}

	var results [64]frontend.Variable
	for i := 0; i < 32; i++ {
		results[i*2] = nibbles[2*i+1]
		results[i*2+1] = nibbles[2*i]
	}

	// inLen <= 62 returns 1
	isShort := LessThan(api, inLen, 63)

	outLen := api.Mul(isShort, api.Sub(inLen, 64))
	outLen = api.Add(outLen, 64)

	return &KeccakOrLiteralHex{
		Output:       results,
		OutputLength: outLen,
	}
}

func Keccak256ForNormalTransactionAsNibbles(
	api frontend.API,
	inLen frontend.Variable, // if input is a padded rlp data, the inlen is the decoded rlp length without padding part
	blocks [keccak.NORMAL_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable,
	roundIndex frontend.Variable,
) *KeccakOrLiteralHex {
	var h = keccak.Keccak256ForNormalTransaction(api, blocks, roundIndex)

	// 64 nibble
	var nibbles [64]frontend.Variable
	for i, r := range h {
		rBits := api.ToBinary(r, 64)

		for j := 0; j < 16; j++ {
			nibbles[i*16+j] = api.FromBinary(rBits[j*4 : (j+1)*4]...)
		}
	}

	var results [64]frontend.Variable
	for i := 0; i < 32; i++ {
		results[i*2] = nibbles[2*i+1]
		results[i*2+1] = nibbles[2*i]
	}

	// inLen <= 62 returns 1
	isShort := LessThan(api, inLen, 63)

	outLen := api.Mul(isShort, api.Sub(inLen, 64))
	outLen = api.Add(outLen, 64)

	return &KeccakOrLiteralHex{
		Output:       results,
		OutputLength: outLen,
	}
}

func Keccak256ForMaxTransactionAsNibbles(
	api frontend.API,
	inLen frontend.Variable, // if input is a padded rlp data, the inlen is the decoded rlp length without padding part
	blocks [keccak.MAX_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable,
	roundIndex frontend.Variable,
) *KeccakOrLiteralHex {

	var h = keccak.Keccak256ForMaxTransaction(api, blocks, roundIndex)

	// 64 nibble
	var nibbles [64]frontend.Variable
	for i, r := range h {
		rBits := api.ToBinary(r, 64)

		for j := 0; j < 16; j++ {
			nibbles[i*16+j] = api.FromBinary(rBits[j*4 : (j+1)*4]...)
		}
	}

	var results [64]frontend.Variable
	for i := 0; i < 32; i++ {
		results[i*2] = nibbles[2*i+1]
		results[i*2+1] = nibbles[2*i]
	}

	// inLen <= 62 returns 1
	isShort := LessThan(api, inLen, 63)

	outLen := api.Mul(isShort, api.Sub(inLen, 64))
	outLen = api.Add(outLen, 64)

	return &KeccakOrLiteralHex{
		Output:       results,
		OutputLength: outLen,
	}
}

func Equal(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func LessThan(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(api.Cmp(a, b), 1))
}

func ArrayEqual(api frontend.API, a []frontend.Variable, b []frontend.Variable, maxLength int, targetLength frontend.Variable) frontend.Variable {
	api.AssertIsLessOrEqual(maxLength, len(a))
	api.AssertIsLessOrEqual(maxLength, len(b))

	var matchSum []frontend.Variable
	for i := 0; i < maxLength; i++ {
		if i == 0 {
			matchSum = append(matchSum, Equal(api, a[i], b[i]))
		} else {
			matchSum = append(matchSum, api.Add(matchSum[i-1], Equal(api, a[i], b[i])))
		}
	}

	var input [][]frontend.Variable
	input = append(input, []frontend.Variable{0})
	for i := 0; i < maxLength; i++ {
		input[0] = append(input[0], matchSum[i])
	}

	multiplexer := Multiplexer(api, targetLength, 1, maxLength+1, input)
	return Equal(api, targetLength, multiplexer[0])
}

func LogCeil(n int) int {
	var nTemp = n
	for i := 0; i < 254; i++ {
		if nTemp == 0 {
			return i
		}
		nTemp = nTemp / 2
	}
	return 254
}

type SubArray struct {
	nIn       int // hex length, for ethereum storage it's 32bytes
	maxSelect int // hex length, for ethereum storage it's 32bytes
	nInBits   int // log ceil max hex length
}

func NewSubArray(nIn int, maxSelect int, nInBits int) *SubArray {
	var rlp = &SubArray{}
	rlp.nIn = nIn
	rlp.maxSelect = maxSelect
	rlp.nInBits = nInBits

	return rlp
}

func (subArray *SubArray) SubArray(api frontend.API, in []frontend.Variable, from frontend.Variable, end frontend.Variable) ([]frontend.Variable, frontend.Variable) {
	// from <= end
	api.AssertIsLessOrEqual(from, end)

	// end <= nIn
	api.AssertIsLessOrEqual(end, subArray.nIn)

	// end - from <= maxSelect
	api.AssertIsLessOrEqual(api.Sub(end, from), subArray.maxSelect)

	outLength := api.Sub(end, from)

	n2b := api.ToBinary(from)

	var shifts [][]frontend.Variable
	for i := 0; i < subArray.nIn; i++ {
		shifts = append(shifts, make([]frontend.Variable, 7))
	}
	for i := 0; i < subArray.nInBits; i++ {
		for j := 0; j < subArray.nIn; j++ {
			if i == 0 {
				tmpIndex := (j + 1<<i) % subArray.nIn
				/// n2b.out[idx] * (in[tempIdx] - in[j]) + in[j]
				shifts[j][i] = api.Add(api.Mul(n2b[i], api.Sub(in[tmpIndex], in[j])), in[j])
			} else {
				prevIndex := i - 1
				tmpIndex := (j + 1<<i) % subArray.nIn
				// shifts[idx][j] <== n2b.out[idx] * (shifts[prevIdx][tempIdx] - shifts[prevIdx][j]) + shifts[prevIdx][j];
				shifts[j][i] = api.Add(api.Mul(n2b[i], api.Sub(shifts[tmpIndex][prevIndex], shifts[j][prevIndex])), shifts[j][prevIndex])
			}
		}
	}
	var output []frontend.Variable
	for i := 0; i < subArray.maxSelect; i++ {
		output = append(output, shifts[i][subArray.nInBits-1])
	}

	log.Debug(output)
	return output, outLength

	// // barrel shifter
	// var shifts [64][7]frontend.Variable

	// for i := 0; i < r.nInBits; i++ {
	// 	var nb = r.api.ToBinary(i, r.nInBits)
	// 	log.Info(nb)
	// 	for j := 0; j < r.nIn; j++ {
	// 		if i == 0 {
	// 			var tempIdx = (j + (1 << i)) % r.nIn
	// 			prefix := r.api.Mul(r.api.Sub(in[tempIdx], in[j]), nb[i])
	// 			shifts[j][i] = r.api.Add(prefix, in[j])
	// 		} else {
	// 			var prevIdx = i - 1
	// 			var tempIdx = (j + (1 << i)) % r.nIn
	// 			ret := r.api.Mul(nb[i], r.api.Sub(shifts[tempIdx][prevIdx], shifts[j][prevIdx]))
	// 			shifts[j][i] = r.api.Add(ret, shifts[j][prevIdx])
	// 		}

	// 	}
	// }
	// log.Info(shifts)
	// var out []frontend.Variable
	// for i := 0; i < r.maxSelect; i++ {
	// 	out = append(out, shifts[i][r.nInBits-1])
	// }

	// var outLen = r.api.Sub(end, from)
	// return out, outLen, nil
}
