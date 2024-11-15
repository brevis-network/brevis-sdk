package utils

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark/frontend"

	"github.com/ethereum/go-ethereum/common"
	ec "github.com/ethereum/go-ethereum/common"
)

var (
	// ZeroAddr is all 0s
	ZeroAddr common.Address
	// ZeroAddrHex is string of 20 0s
	ZeroAddrHex = Addr2Hex(ZeroAddr)
	// ZeroBigInt is big.NewInt(0)
	ZeroBigInt = big.NewInt(0)
	// ZeroHash is all 0s
	ZeroHash common.Hash
	// HashLength is the expected length of the hash
	HashLength = 32
)

// ========== Hex/Bytes ==========

// IsValidTxHash verifies whether a string can represent a valid hash or not.
func IsValidTxHash(txHash string) bool {
	if txHash == "" {
		return false
	}
	if has0xPrefix(txHash) {
		txHash = txHash[2:]
	}
	return len(txHash) == 2*HashLength && isHex(txHash)
}

// isHex validates whether each byte is valid hexadecimal string.
func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// Hex2Bytes supports hex string with or without 0x prefix
// Calls hex.DecodeString directly and ignore err
// similar to ec.FromHex but better
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

// Bytes2Hex returns hex string without 0x prefix
func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

func Bytes2Hex0x(b []byte) string {
	return "0x" + Bytes2Hex(b)
}

func ArrayHex2Hash(in []string) [][32]byte {
	var ret [][32]byte
	for _, e := range in {
		ret = append(ret, Hex2Hash(e))
	}
	return ret
}

func ArrayBytes2Hex0x(in [][]byte) []string {
	var ret []string
	for _, e := range in {
		ret = append(ret, Bytes2Hex0x(e[:]))
	}
	return ret
}

// ========== Address ==========

// Hex2Addr accepts hex string with or without 0x prefix and return Address
func Hex2Addr(s string) common.Address {
	return ec.HexToAddress(s)
}

// Addr2Hex returns hex without 0x
func Addr2Hex(a common.Address) string {
	return Bytes2Hex(a[:])
}

func Addr2Hex0x(a common.Address) string {
	return "0x" + Addr2Hex(a)
}

// Bytes2Addr returns Address from b
// Addr.Bytes() does the reverse
func Bytes2Addr(b []byte) common.Address {
	return ec.BytesToAddress(b)
}

// Bytes2AddrHex returns hex without 0x
func Bytes2AddrHex(b []byte) string {
	return Addr2Hex(Bytes2Addr(b))
}

func Bytes2AddrHex0x(b []byte) string {
	return "0x" + Bytes2AddrHex(b)
}

// FormatAddrHex formats a string into standard Addr string
func FormatAddrHex(s string) string {
	return Addr2Hex(Hex2Addr(s))
}

// ========== Hash ==========

// Hex2Hash accepts hex string with or without 0x prefix and return Hash
func Hex2Hash(s string) common.Hash {
	return ec.HexToHash(s)
}

// Bytes2Hash converts bytes to Hash
func Bytes2Hash(b []byte) common.Hash {
	return ec.BytesToHash(b)
}

func Strings2bytes(rs []string) (ret [][]byte) {
	for _, r := range rs {
		ret = append(ret, Hex2Bytes(r))
	}
	return
}

func Hex2BigInt(s string) *big.Int {
	b := Hex2Bytes(s)
	return new(big.Int).SetBytes(b)
}

// if in is 20 bytes, return directly. otherwise return a new []byte w/ len 20, left pad 0x00..[in]
// if len(in)>20, panic
func Pad20Bytes(in []byte) []byte {
	origLen := len(in)
	if origLen == 20 {
		return in
	}
	if origLen > 20 {
		panic(fmt.Sprintf("%x len %d > 20", in, origLen))
	}
	ret := make([]byte, 20)
	copy(ret[20-origLen:], in)
	return ret
}

func Pad32Bytes(in []byte) []byte {
	origLen := len(in)
	if origLen == 32 {
		return in
	}
	if origLen > 32 {
		panic(fmt.Sprintf("%x len %d > 32", in, origLen))
	}
	ret := make([]byte, 32)
	copy(ret[32-origLen:], in)
	return ret
}

func Reverse[S ~[]E, E any](s S) S {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func GetHexArray(hexStr string, maxLen int) (res []frontend.Variable) {
	for i := 0; i < maxLen; i++ {
		if i < len(hexStr) {
			intValue, err := strconv.ParseInt(string(hexStr[i]), 16, 64)
			if err != nil {
				panic("invalid hexadecimal character: " + string(hexStr[i]))
			}
			res = append(res, intValue)
		} else {
			res = append(res, 0)
		}
	}
	return
}
