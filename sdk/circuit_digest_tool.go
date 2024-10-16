package sdk

import (
	"fmt"
	pgoldilocks "github.com/OpenAssetStandards/poseidon-goldilocks-go"
	"github.com/brevis-network/brevis-sdk/common/utils"
	zkhashutils "github.com/brevis-network/zk-hash/utils"
	"math/big"
)

var (
	ReceiptD     = new(big.Int).SetUint64(uint64(1))
	StorageD     = new(big.Int).SetUint64(uint64(2))
	TransactionD = new(big.Int).SetUint64(uint64(3))

	ReceiptVkHashHex     = "0x2a4033f89d43af00c4b6a9a19cd8680e859f6d72ced652e9208a6c599244a455"
	StorageVkHashHex     = "0x00b248c7834c19d4945ef79014704154392115ad1b5ae616ee2fbc24b6280fb7"
	TransactionVkHashHex = "0x1f492045728b8f39069030857cb307b4873fd3d9c566436935ffdafca19cc326"
	MiddleNodeVkHashHex  = "0x001c0bf04a06901970f9774c51ae5fa570a874836b705d0a9587769fe7f523ce"

	ReceiptCircuitDigestHash        = "0x0c4ee30e1507f305c335d97b6dd529a212aa62084638bdf22e0a35b57514bf8f"
	TxCircuitDigestHash             = "0x547cca33d38ea15e0b40901a89add6c47f2e3725317cf5493b3845ceb74b0edd"
	StorageCircuitDigestHash        = "0xe7396c8401f2520fc8fa69a562f592ed701e25df5444b6b65012493d26e9085c"
	P2AggRecursionCircuitDigestHash = ""
	P2Bn128WrapCircuitDigestHash    = ""

	ReceiptVkHash     = utils.Hex2BigInt(ReceiptVkHashHex)
	StorageVkHash     = utils.Hex2BigInt(StorageVkHashHex)
	TransactionVkHash = utils.Hex2BigInt(TransactionVkHashHex)
	MiddleNodeVkHash  = utils.Hex2BigInt(MiddleNodeVkHashHex)

	ReceiptNode = Hash2HashDigestNode{
		CircuitDigest: ReceiptD,
		VkHash:        ReceiptVkHash,
	}

	StorageNode = Hash2HashDigestNode{
		CircuitDigest: StorageD,
		VkHash:        StorageVkHash,
	}

	TransactionNode = Hash2HashDigestNode{
		CircuitDigest: TransactionD,
		VkHash:        TransactionVkHash,
	}
)

type Hash2HashDigestNode struct {
	CircuitDigest *big.Int
	VkHash        *big.Int
}

func GetHash2HashCircuitDigest(receiptCount, storageCount, transactionCount int) (*big.Int, error) {
	receiptLeafCount, storageLeafCount, transactionLeafCount, totalLeafCount, err := GetAndCheckLeafCount(receiptCount, storageCount, transactionCount)
	if err != nil {
		return nil, err
	}

	var totalLeafs []Hash2HashDigestNode
	for i := 0; i < receiptLeafCount; i++ {
		totalLeafs = append(totalLeafs, ReceiptNode)
	}
	for i := 0; i < storageLeafCount; i++ {
		totalLeafs = append(totalLeafs, StorageNode)
	}
	for i := 0; i < transactionLeafCount; i++ {
		totalLeafs = append(totalLeafs, TransactionNode)
	}
	if len(totalLeafs) != totalLeafCount {
		return nil, fmt.Errorf("len(totalLeafs) != totalLeafCount, %d %d", totalLeafs, totalLeafCount)
	}
	elementCount := totalLeafCount
	for {
		if elementCount == 1 {
			return totalLeafs[0].CircuitDigest, nil
		}
		for i := 0; i < elementCount/2; i++ {
			parent, hashErr := CalOneHash2HashNodeDigest(totalLeafs[2*i], totalLeafs[2*i+1])
			if hashErr != nil {
				return nil, fmt.Errorf("fail to hash in CalOneHash2HashNodeDigest, %d %d -> %d err: %v", 2*i, 2*i+1, i, hashErr)
			}
			totalLeafs[i] = Hash2HashDigestNode{
				CircuitDigest: parent,
				VkHash:        MiddleNodeVkHash,
			}
		}
		elementCount = elementCount / 2
	}
}

func CalOneHash2HashNodeDigest(left, right Hash2HashDigestNode) (*big.Int, error) {
	poseidonHasher := zkhashutils.NewPoseidonBn254()
	poseidonHasher.Write(left.CircuitDigest)
	poseidonHasher.Write(right.CircuitDigest)
	poseidonHasher.Write(left.VkHash)
	poseidonHasher.Write(right.VkHash)

	return poseidonHasher.Sum()
}

type Plonky2DigestNode struct {
	PubCircuitDigest *big.Int
	CurCircuitDigest *big.Int
}

func GetPlonky2CircuitDigest(receiptCount, storageCount, transactionCount int) (*pgoldilocks.HashOut256, error) {
	/*receiptLeafCount, storageLeafCount, transactionLeafCount, totalLeafCount, err := GetAndCheckLeafCount(receiptCount, storageCount, transactionCount)
	if err != nil {
		return nil, err
	}*/
	glPoseidonHashOut, err := pgoldilocks.HashNoPadU64Array([]uint64{})
	return glPoseidonHashOut, err
}

func GetAndCheckLeafCount(receiptCount, storageCount, transactionCount int) (receiptLeafCount int, storageLeafCount int, transactionLeafCount int, totalLeafCount int, err error) {
	if receiptCount%32 != 0 {
		return 0, 0, 0, 0, fmt.Errorf("receipt count is not n * 32")
	}
	receiptLeafCount = receiptCount / 32

	if storageCount%32 != 0 {
		return 0, 0, 0, 0, fmt.Errorf("storage count is not n * 32")
	}
	storageLeafCount = storageCount / 32

	if transactionCount%32 != 0 {
		return 0, 0, 0, 0, fmt.Errorf("transaction count is not n * 32")
	}
	transactionLeafCount = transactionCount / 32

	totalLeafCount = receiptLeafCount + storageLeafCount + transactionLeafCount
	if !CheckNumberPowerOfTwo(totalLeafCount) {
		return 0, 0, 0, 0, fmt.Errorf("leaf count n is not power of 2, totalLeafCount: %d", totalLeafCount)
	}

	return receiptLeafCount, storageLeafCount, transactionLeafCount, totalLeafCount, nil
}
