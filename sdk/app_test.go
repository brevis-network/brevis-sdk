package sdk

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestDataMarshalUnmarshal(t *testing.T) {
	tx := TransactionPos{
		Hash: common.HexToHash("0x6a70343b232c18280821471baf247ce69fbf740893ec9fb80a47bda7f4ea4a2f"),
	}
	txJson, err := json.MarshalIndent(tx, "", "  ")
	check(err)
	fmt.Printf("%s\n", txJson)
	tx2 := TransactionPos{}
	err = json.Unmarshal(txJson, &tx2)
	check(err)

	receipt := ReceiptPos{
		TxHash: tx.Hash,
		Fields: []LogFieldPos{
			{
				LogPos:     2,
				IsTopic:    false,
				FieldIndex: 3,
			},
			{
				LogPos:     3,
				IsTopic:    false,
				FieldIndex: 4,
			},
		},
	}
	rJson, err := json.MarshalIndent(receipt, "", "  ")
	check(err)
	fmt.Printf("%s\n", rJson)
	receipt2 := ReceiptPos{}
	err = json.Unmarshal(rJson, &receipt2)
	check(err)

	storage := StoragePos{
		BlockNum: big.NewInt(2),
		Address:  common.HexToAddress("0x1345c8a6b99536531F1fa3cfe37D8A5B7Fc859aA"),
		Slot:     common.HexToHash("0x64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107"),
	}
	sJson, err := json.MarshalIndent(storage, "", "  ")
	check(err)
	fmt.Printf("%s\n", sJson)
	storage2 := StoragePos{}
	err = json.Unmarshal(sJson, &storage2)
	check(err)
}
