package nftOwnership

import (
	"github.com/brevis-network/brevis-sdk/sdk"
)

type AppCircuit struct {
	NFTContractAddr sdk.Uint248
	OwnerAddr       sdk.Uint248
	TokenID         sdk.Uint248
}

var _ sdk.AppCircuit = &AppCircuit{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// We need to check receipt logs for Transfer events
	// Allocate space for checking transfer events
	return 1, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	// Create a data stream from receipts
	receipts := sdk.NewDataStream(api, in.Receipts)

	// Get the receipt containing the Transfer event
	receipt := sdk.GetUnderlying(receipts, 0)

	// ERC721 Transfer event signature:
	// event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
	// Topics: [0] = event signature hash
	//         [1] = from address
	//         [2] = to address (the owner we're verifying)
	//         [3] = tokenId

	// Verify Field 0: Contract address
	api.Uint248.AssertIsEqual(receipt.Fields[0].Contract, c.NFTContractAddr)

	// Verify Field 0: "to" address (topic index 2)
	api.Uint248.AssertIsEqual(receipt.Fields[0].IsTopic, sdk.ConstUint248(1))
	api.Uint248.AssertIsEqual(receipt.Fields[0].Index, sdk.ConstUint248(2))
	api.Uint248.AssertIsEqual(api.ToUint248(receipt.Fields[0].Value), c.OwnerAddr)

	// Verify Field 1: tokenId (topic index 3)
	api.Uint248.AssertIsEqual(receipt.Fields[1].Contract, c.NFTContractAddr)
	api.Uint248.AssertIsEqual(receipt.Fields[1].IsTopic, sdk.ConstUint248(1))
	api.Uint248.AssertIsEqual(receipt.Fields[1].Index, sdk.ConstUint248(3))
	api.Uint248.AssertIsEqual(api.ToUint248(receipt.Fields[1].Value), c.TokenID)

	// Verify both fields are from the same log entry
	api.Uint32.AssertIsEqual(receipt.Fields[0].LogPos, receipt.Fields[1].LogPos)

	// Output the verified ownership information
	api.OutputAddress(c.OwnerAddr)                            // Owner address
	api.OutputAddress(c.NFTContractAddr)                      // NFT contract address
	api.OutputUint(248, c.TokenID)                            // Token ID
	api.OutputUint(64, api.ToUint248(receipt.BlockNum))       // Block number of transfer

	return nil
}
