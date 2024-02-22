package sdk

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"testing"
)

func TestDataMarshalUnmarshal(t *testing.T) {
	value, _ := new(big.Int).SetString("12341231231231231231231231233", 10)
	tx := TransactionData{
		Hash:                 common.HexToHash("0x6a70343b232c18280821471baf247ce69fbf740893ec9fb80a47bda7f4ea4a2f"),
		ChainId:              big.NewInt(1),
		BlockNum:             big.NewInt(2),
		Nonce:                3,
		MaxPriorityFeePerGas: big.NewInt(4),
		GasPriceOrFeeCap:     big.NewInt(6),
		GasLimit:             6,
		From:                 common.HexToAddress("0x1345c8a6b99536531F1fa3cfe37D8A5B7Fc859aA"),
		To:                   common.HexToAddress("0x164Ef8f77e1C88Fb2C724D3755488bE4a3ba4342"),
		Value:                value,
	}
	txJson, err := json.MarshalIndent(tx, "", "  ")
	check(err)
	fmt.Printf("%s\n", txJson)
	tx2 := TransactionData{}
	err = json.Unmarshal(txJson, &tx2)
	check(err)

	receipt := ReceiptData{
		BlockNum: big.NewInt(1),
		TxHash:   tx.Hash,
		Fields: [3]LogFieldData{
			{
				Contract:   common.HexToAddress("0x1345c8a6b99536531F1fa3cfe37D8A5B7Fc859aA"),
				LogIndex:   2,
				EventID:    common.HexToHash("0x6a70343b232c18280821471baf247ce69fbf740893ec9fb80a47bda7f4ea4a2f"),
				IsTopic:    false,
				FieldIndex: 3,
				Value:      common.BytesToHash([]byte{1}),
			},
			{
				Contract:   common.HexToAddress("0x164Ef8f77e1C88Fb2C724D3755488bE4a3ba4342"),
				LogIndex:   3,
				EventID:    common.HexToHash("0x64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107"),
				IsTopic:    false,
				FieldIndex: 4,
				Value:      common.BytesToHash([]byte{2}),
			},
		},
	}
	rJson, err := json.MarshalIndent(receipt, "", "  ")
	check(err)
	fmt.Printf("%s\n", rJson)
	receipt2 := ReceiptData{}
	err = json.Unmarshal(rJson, &receipt2)
	check(err)

	storage := StorageData{
		BlockNum: big.NewInt(2),
		Address:  common.HexToAddress("0x1345c8a6b99536531F1fa3cfe37D8A5B7Fc859aA"),
		Key:      common.HexToHash("0x64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107"),
		Value:    common.BytesToHash([]byte{2}),
	}
	sJson, err := json.MarshalIndent(storage, "", "  ")
	check(err)
	fmt.Printf("%s\n", sJson)
	storage2 := StorageData{}
	err = json.Unmarshal(sJson, &storage2)
	check(err)
}
