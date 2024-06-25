package gwproto

import (
	"bytes"

	"github.com/cbergoon/merkletree"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func (data *ProofData) CalculateHash() ([]byte, error) {
	var b []byte
	b = append(b, common.Hex2Bytes(data.CommitHash)...)
	b = append(b, common.Hex2Bytes(data.SmtRoot)...)
	b = append(b, common.Hex2Bytes(data.VkHash)...)
	b = append(b, common.Hex2Bytes(data.AppCommitHash)...)
	b = append(b, common.Hex2Bytes(data.AppVkHash)...)
	return crypto.Keccak256(b), nil
}

func (data *ProofData) Equals(other merkletree.Content) (bool, error) {
	myHash, _ := data.CalculateHash()
	otherHash, _ := other.CalculateHash()
	return bytes.Equal(myHash, otherHash), nil
}
