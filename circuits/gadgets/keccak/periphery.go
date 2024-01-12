package keccak

import (
	"github.com/consensys/gnark/frontend"
)

func Uint64s2Blocks(padded []uint64) [MAX_ROUNDS][17]frontend.Variable {
	ret := [MAX_ROUNDS][17]frontend.Variable{}
	for i, el := range padded {
		ret[i/17][i%17] = el
	}
	for i := len(padded); i < MAX_ROUNDS*17; i++ {
		ret[i/17][i%17] = 0
	}
	return ret
}

func Pad101(data []byte) []uint64 {
	return Bytes2Uint64s(Pad101Bytes(data))
}

func Pad101Bytes(data []byte) []byte {
	miss := 136 - len(data)%136
	if len(data)%136 == 0 {
		miss = 136
	}
	data = append(data, 1)
	for i := 0; i < miss-1; i++ {
		data = append(data, 0)
	}
	data[len(data)-1] ^= 0x80
	return data
}

func Bytes2BlockBits(bytes []byte) (bits []uint8) {
	if len(bytes)%136 != 0 {
		panic("invalid length")
	}
	return Bytes2Bits(bytes)
}

func Bytes2Bits(bytes []byte) (bits []uint8) {
	if len(bytes)%8 != 0 {
		panic("invalid length")
	}
	for i := 0; i < len(bytes); i++ {
		bits = append(bits, byte2Bits(bytes[i])...)
	}
	return
}

// bytes2Bits outputs bits in little-endian
func byte2Bits(b byte) (bits []uint8) {
	for i := 0; i < 8; i++ {
		bits = append(bits, (uint8(b)>>i)&1)
	}
	return
}

func Bytes2Uint64(bytes []byte) uint64 {
	if len(bytes) != 8 {
		panic("bytes len must be 8")
	}
	ret := uint64(0)
	for i := 0; i < 8; i++ {
		ret |= uint64(bytes[i]) << (i * 8)
	}
	return ret
}

func Bytes2Uint64s(bytes []byte) []uint64 {
	if len(bytes)%8 != 0 {
		panic("bytes len must be multiple of 8")
	}
	ret := []uint64{}
	for i := 0; i < len(bytes); i += 8 {
		ret = append(ret, Bytes2Uint64(bytes[i:i+8]))
	}
	return ret
}

// NibblesToU64Array get Keccak256 blocks, each round with a size-17 uint64
func NibblesToU64Array(api frontend.API, nibbles []frontend.Variable) [MAX_ROUNDS][17]frontend.Variable {
	const (
		nibblesPerU64 = 16
		u64sPerRound  = 17
	)
	var ret [MAX_ROUNDS][u64sPerRound]frontend.Variable

	var u64s []frontend.Variable
	start := len(nibbles) * 4 / 64
	for i := 0; i < start; i++ {
		var u64bits []frontend.Variable

		// Every 16 nibbles forms an uint64
		for j := 0; j < 8; j++ {
			var perBytes []frontend.Variable
			perBytePart1 := api.ToBinary(nibbles[i*nibblesPerU64+j*2], 4)
			perBytePart2 := api.ToBinary(nibbles[i*nibblesPerU64+j*2+1], 4)

			perBytes = append(perBytes, perBytePart2...)
			perBytes = append(perBytes, perBytePart1...)

			u64bits = append(u64bits, perBytes...)
		}

		u64s = append(u64s, api.FromBinary(u64bits...))
	}

	for i, el := range u64s {
		ret[i/17][i%17] = el
	}

	for i := len(u64s); i < MAX_ROUNDS*17; i++ {
		ret[i/17][i%17] = 0
	}

	return ret
}

func NibblesToU64ArrayForNormalTransactionLeafValue(api frontend.API, nibbles []frontend.Variable) [NORMAL_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable {
	const (
		nibblesPerU64 = 16
		u64sPerRound  = 17
	)
	var ret [NORMAL_TRANSACTION_LEAF_ROUNDS][u64sPerRound]frontend.Variable

	var u64s []frontend.Variable
	start := len(nibbles) * 4 / 64
	for i := 0; i < start; i++ {
		var u64bits []frontend.Variable

		// Every 16 nibbles forms an uint64
		for j := 0; j < 8; j++ {
			var perBytes []frontend.Variable
			perBytePart1 := api.ToBinary(nibbles[i*nibblesPerU64+j*2], 4)
			perBytePart2 := api.ToBinary(nibbles[i*nibblesPerU64+j*2+1], 4)

			perBytes = append(perBytes, perBytePart2...)
			perBytes = append(perBytes, perBytePart1...)

			u64bits = append(u64bits, perBytes...)
		}

		u64s = append(u64s, api.FromBinary(u64bits...))
	}

	for i, el := range u64s {
		ret[i/17][i%17] = el
	}

	for i := len(u64s); i < NORMAL_TRANSACTION_LEAF_ROUNDS*17; i++ {
		ret[i/17][i%17] = 0
	}

	return ret
}

func NibblesToU64ArrayForMaxTransactionLeafValue(api frontend.API, nibbles []frontend.Variable) [MAX_TRANSACTION_LEAF_ROUNDS][17]frontend.Variable {
	const (
		nibblesPerU64 = 16
		u64sPerRound  = 17
	)
	var ret [MAX_TRANSACTION_LEAF_ROUNDS][u64sPerRound]frontend.Variable

	var u64s []frontend.Variable
	start := len(nibbles) * 4 / 64
	for i := 0; i < start; i++ {
		var u64bits []frontend.Variable

		// Every 16 nibbles forms an uint64
		for j := 0; j < 8; j++ {
			var perBytes []frontend.Variable
			perBytePart1 := api.ToBinary(nibbles[i*nibblesPerU64+j*2], 4)
			perBytePart2 := api.ToBinary(nibbles[i*nibblesPerU64+j*2+1], 4)

			perBytes = append(perBytes, perBytePart2...)
			perBytes = append(perBytes, perBytePart1...)

			u64bits = append(u64bits, perBytes...)
		}

		u64s = append(u64s, api.FromBinary(u64bits...))
	}

	for i, el := range u64s {
		ret[i/17][i%17] = el
	}

	for i := len(u64s); i < MAX_TRANSACTION_LEAF_ROUNDS*17; i++ {
		ret[i/17][i%17] = 0
	}

	return ret
}

func GetKeccakRoundIndex(dataLenInHex int) int {
	var chunkSizeInHex = 272
	chunkNum := (dataLenInHex + chunkSizeInHex - 1) / chunkSizeInHex
	if chunkNum > 0 {
		chunkNum--
	}
	return chunkNum
}

func GetRoundIndex(bitsLen int) int {
	return (bitsLen + 8) / 1088
}

func PadBits101(api frontend.API, data []frontend.Variable, maxRound int) []frontend.Variable {
	var padBits []frontend.Variable
	padBits = append(padBits, data...)
	var missedLen = 1088 - len(data)%1088
	var zeroBitLen = missedLen - 8*2

	padBits = append(padBits, api.ToBinary(1, 8)...) // 1000, 0000
	for i := 0; i < zeroBitLen; i++ {
		padBits = append(padBits, 0) //00...0000
	}
	padBits = append(padBits, api.ToBinary(128, 8)...) // 0000 0001

	padZeroLen := maxRound*1088 - len(padBits)

	for i := 0; i < padZeroLen; i++ {
		padBits = append(padBits, 0)
	}
	return padBits
}
