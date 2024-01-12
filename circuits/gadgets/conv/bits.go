package conv

import (
	"github.com/celer-network/brevis-sdk/circuits/gadgets/utils"

	"github.com/consensys/gnark/frontend"
)

func Bits2Bytes2(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bytes := []frontend.Variable{}
	for i := 0; i < len(bits); i += 8 {
		bytes = append(bytes, api.FromBinary(utils.Flip(bits[i:i+8])...))
	}
	return bytes
}

func Bits2Bytes(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bytes := []frontend.Variable{}
	for i := 0; i < len(bits); i += 8 {
		bytes = append(bytes, api.FromBinary(bits[i:i+8]...))
	}
	return bytes
}

func Bits2BytesArray(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bytes := []frontend.Variable{}
	for i := len(bits); i > 0; i -= 8 {
		bytes = append(bytes, api.FromBinary(bits[i-8:i]...))
	}
	return bytes
}

// convert 256 bits to two uin128s
// this function assumes a 254-bit scalar field.
// this can be used for shortening public input length.
// bits are arranged to match
//
//	[2]frontend.Variable{
//			new(big.Int).SetBytes(h[:16]),
//			new(big.Int).SetBytes(h[16:]),
//	}
func Bits2Uint128s(api frontend.API, bits [256]frontend.Variable) [2]frontend.Variable {
	h := utils.FlipSubSlice(bits[:], 8)
	return [2]frontend.Variable{
		api.FromBinary(utils.Flip(h[:128])...),
		api.FromBinary(utils.Flip(h[128:])...),
	}
}

func Bits2Nibbles(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bytes := []frontend.Variable{}
	for i := 0; i < len(bits); i += 8 {
		bytes = append(bytes, api.FromBinary(bits[i:i+4]))
	}
	return bytes
}
