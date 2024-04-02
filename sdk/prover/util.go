package prover

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
)

// Hex2Addr accepts hex string with or without 0x prefix and return Addr
func Hex2Addr(s string) common.Address {
	return common.BytesToAddress(Hex2Bytes(s))
}

func Hex2Bytes(s string) (b []byte) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	// hex.DecodeString expects an even-length string
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ = hex.DecodeString(s)
	return b
}

func Hex2Hash(s string) common.Hash {
	return common.BytesToHash(Hex2Bytes(s))
}

func Bytes2Hash(b []byte) common.Hash {
	return common.BytesToHash(b)
}
