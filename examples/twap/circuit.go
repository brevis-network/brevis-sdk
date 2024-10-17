package twap

import (
	"fmt"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
)

type AppCircuit struct{}

var _ sdk.AppCircuit = &AppCircuit{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// This demo app is only going to use blockTimestampLast, price0CumulativeLast and
	// price1CumulativeLast from two different blocks. These three storage variables takes three
	// different contract slots, so we need 6 storage slots in total.
	return 0, 96, 0
}

var UniswapV2PairUsdcEth = sdk.ConstUint248(
	common.HexToAddress("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"))

var SlotBlockTimestampLastAndReserves = sdk.ConstFromBigEndianBytes(
	common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000008"))

var SlotPrice0CumulativeLast = sdk.ConstFromBigEndianBytes(
	common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000009"))

var SlotPrice1CumulativeLast = sdk.ConstFromBigEndianBytes(
	common.FromHex("0x000000000000000000000000000000000000000000000000000000000000000a"))

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	slots := sdk.NewDataStream(api, in.StorageSlots)
	var u248 = api.Uint248
	var b32 = api.Bytes32
	var u32 = api.Uint32

	// group every 3 storage slot data, each group represents a tuple
	windowed := sdk.WindowUnderlying(slots, 3)

	sdk.AssertEach(windowed, func(cur sdk.List[sdk.StorageSlot]) sdk.Uint248 {
		blockNum := cur[0].BlockNum
		return u248.And(
			// check contract of the storage slots are the ETH/USDC pair
			u248.IsEqual(cur[0].Contract, UniswapV2PairUsdcEth),
			u248.IsEqual(cur[1].Contract, UniswapV2PairUsdcEth),
			u248.IsEqual(cur[2].Contract, UniswapV2PairUsdcEth),

			// this slot packs the three vars (reserve0, reserve1, blockTimestampLast)
			b32.IsEqual(cur[0].Slot, SlotBlockTimestampLastAndReserves),
			b32.IsEqual(cur[1].Slot, SlotPrice0CumulativeLast),
			b32.IsEqual(cur[2].Slot, SlotPrice1CumulativeLast),

			// check block numbers are consistent within the group
			api.ToUint248(u32.IsEqual(cur[1].BlockNum, blockNum)),
			api.ToUint248(u32.IsEqual(cur[2].BlockNum, blockNum)),
		)
	})

	a := sdk.GetUnderlying(windowed, 0)
	blockTimestampLastA := decodeBlockTimestampLast(api, a[0].Value)
	price0CumulativeLastA := api.ToUint248(a[1].Value)
	price1CumulativeLastA := api.ToUint248(a[2].Value)

	b := sdk.GetUnderlying(windowed, 1)
	blockTimestampLastB := decodeBlockTimestampLast(api, b[0].Value)
	price0CumulativeLastB := api.ToUint248(b[1].Value)
	price1CumulativeLastB := api.ToUint248(b[2].Value)

	fmt.Println(price0CumulativeLastA, price1CumulativeLastA, price0CumulativeLastB, price1CumulativeLastB)

	fromBlock := a[0].BlockNum
	toBlock := b[0].BlockNum
	u32.AssertIsEqual(u32.IsGreaterThan(fromBlock, toBlock), sdk.ConstUint32(0))

	// the results are uq112x112 fixed point numbers
	// to get a human readable twap for token0, do:
	// twap / 2^112 / token1_decimal * token0_decimal

	timeElapsed := u248.Sub(blockTimestampLastB, blockTimestampLastA)

	price0Cumulative := u248.Sub(price0CumulativeLastB, price0CumulativeLastA)
	token0Twap, _ := u248.Div(price0Cumulative, timeElapsed)

	price1Cumulative := u248.Sub(price1CumulativeLastB, price1CumulativeLastA)
	token1Twap, _ := u248.Div(price1Cumulative, timeElapsed)

	fmt.Println(price0Cumulative, price1Cumulative)

	api.OutputUint(248, token0Twap)
	api.OutputUint(248, token1Twap)
	api.OutputUint32(32, fromBlock)
	api.OutputUint(32, timeElapsed)

	return nil
}

func decodeBlockTimestampLast(api *sdk.CircuitAPI, data sdk.Bytes32) sdk.Uint248 {
	bits := api.Bytes32.ToBinary(data)
	blockTimestampLast := api.Bytes32.FromBinary(bits[224:]...) // blockTimestampLast is a uint32
	return api.ToUint248(blockTimestampLast)
}
