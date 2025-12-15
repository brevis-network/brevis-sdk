# Uniswap V2 Swap Volume Circuit

## Overview

This circuit proves that a user traded **≥ minimum threshold volume** on Uniswap V2 without revealing:
- Individual swap amounts
- Exact total volume (only proves it meets threshold)
- Transaction details

**Use Cases:**
- Trading rewards eligibility
- Volume-based tiering systems
- Trader reputation/badges
- Airdrop qualifications

---

## Circuit Logic

### Input Parameters

```go
type AppCircuit struct {
    UserAddr  sdk.Uint248  // Address to track
    MinVolume sdk.Uint248  // Minimum volume threshold (in wei)
}
```

### Data Sources

- **Receipts**: Up to 10 Swap events from Uniswap V2 WETH/USDC pair
- **Contract**: `0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc` (WETH/USDC pair)
- **Event**: Swap event (signature: `0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822`)

### Algorithm

1. **Filter Swap Events**
   - Contract matches WETH/USDC pair address
   - `to` address (topics[2]) matches UserAddr
   - Verify field is topic index 2

2. **Extract Amounts**
   - Get `amount1Out` from each swap (data field index 3)
   - This represents WETH received by the user

3. **Sum Volume**
   - Sum all `amount1Out` values across filtered swaps
   - Count number of swaps

4. **Assert Threshold**
   - Verify: `totalVolume >= MinVolume`

5. **Output Results**
   - User address
   - Total volume
   - Minimum threshold
   - Number of swaps

---

## Event Structure Reference

### Uniswap V2 Swap Event

```solidity
event Swap(
    address indexed sender,    // topics[1]
    uint amount0In,           // data[0]
    uint amount1In,           // data[1]
    uint amount0Out,          // data[2]
    uint amount1Out,          // data[3]
    address indexed to        // topics[2]
);
```

**Event Signature Hash:**
```
0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822
```

**WETH/USDC Pair Token Order:**
- `token0` = USDC (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)
- `token1` = WETH (0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)

**Why this order?**
Token addresses are sorted: `USDC < WETH` (alphabetically by address)

---

## Circuit Design Decisions

### Why Track "to" Address Instead of "sender"?

The `to` address receives the output tokens, which represents the actual beneficiary of the swap. The `sender` is often a router contract, not the end user.

**Example:**
- User calls UniswapV2Router02
- Router calls pair.swap()
- Swap event has:
  - `sender` = Router address (0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)
  - `to` = User's wallet address

By tracking `to`, we capture actual user trades.

### Why Only amount1Out (WETH)?

For the WETH/USDC pair:
- Trading USDC → WETH: `amount1Out > 0`, `amount0Out = 0`
- Trading WETH → USDC: `amount0Out > 0`, `amount1Out = 0`

This circuit specifically tracks **WETH received** by the user. To track both directions, you'd sum `amount0Out + amount1Out` (with proper decimal handling).

### Why Limit to 10 Swaps?

The `Allocate()` function sets `maxReceipts = 10`. This is a resource allocation decision:
- More receipts = more constraints = longer proving time
- 10 swaps is sufficient for most use cases
- Can be adjusted based on requirements

---

## Example Usage Scenario

**Goal:** Prove user traded ≥ 5 WETH on WETH/USDC pair

**Circuit Inputs:**
```go
AppCircuit{
    UserAddr:  "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    MinVolume: "5000000000000000000", // 5 WETH (18 decimals)
}
```

**Data Collection (via BrevisApp):**
```go
// Collect last 10 Swap events where to = UserAddr
app.AddReceipt(sdk.ReceiptData{
    TxHash:   "0x...",
    Fields: []*sdk.LogFieldData{
        {
            Contract: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
            LogPos:   0,
            IsTopic:  true,
            Index:    2,  // topics[2] = to address
            Value:    userAddr,
        },
        // ... amount1Out field
    },
})
```

**Circuit Proof:**
- Verifies all events are from WETH/USDC pair
- Sums amount1Out from all swaps
- Asserts sum ≥ 5 WETH
- Outputs: address, total volume, threshold, swap count

**On-Chain Result:**
Smart contract receives proof and can:
- Award trading badge
- Distribute rewards
- Enable premium features
- All without knowing exact volume or transactions!

---

## Limitations & Future Improvements

### Current Limitations

1. **Single Pair Only**
   - Hardcoded to WETH/USDC pair
   - Doesn't track other pairs

2. **One-Directional**
   - Only tracks WETH received (amount1Out)
   - Misses USDC received (amount0Out)

3. **No USD Value Calculation**
   - Tracks raw WETH amounts
   - Doesn't convert to USD equivalent

4. **Fixed Receipt Count**
   - Maximum 10 swaps
   - Can't aggregate larger trading history

### Possible Enhancements

**Multi-Pair Support:**
```go
type AppCircuit struct {
    UserAddr  sdk.Uint248
    MinVolume sdk.Uint248
    PairAddrs []sdk.Uint248  // Track multiple pairs
}
```

**Bidirectional Tracking:**
```go
// Sum both directions
totalVolume := sdk.Sum(amount0Outs) + sdk.Sum(amount1Outs)
```

**USD Value Conversion:**
```go
// Use TWAP or spot price to convert to USD
usdValue := calculateUSDValue(wethAmount, twapPrice)
```

**Time Window:**
```go
type AppCircuit struct {
    UserAddr    sdk.Uint248
    MinVolume   sdk.Uint248
    StartBlock  sdk.Uint64
    EndBlock    sdk.Uint64
}

// Filter swaps within block range
// ... verify receipt.BlockNum >= StartBlock && <= EndBlock
```

---

## Circuit File Structure

```
dex-volume/uniswap-v2/
├── circuit.go          # Circuit implementation
└── README.md          # This file
```

---

## Compilation Status

✅ **Compiles Successfully**
- Package: `uniswapv2volume`
- Dependencies: brevis-sdk, go-ethereum
- No compilation errors

❌ **Cannot Test (Gateway Required)**
- Requires Brevis gateway access for circuit digests
- See [WHY_GATEWAY_NEEDED.md](../../WHY_GATEWAY_NEEDED.md)

---

## Related Protocols

This circuit pattern can be adapted for:
- **Uniswap V3**: Similar events, different fee tiers
- **SushiSwap**: Same interface as Uniswap V2
- **PancakeSwap**: BSC version of Uniswap V2
- **Other AMMs**: Any with Swap events

See [protocols/uniswap-v2.md](../../protocols/uniswap-v2.md) for detailed protocol reference.

---

## Next Steps

1. ✅ Implement basic swap volume circuit
2. ⏳ Implement LP tracking circuit
3. ⏳ Implement TWAP oracle circuit
4. ⏳ Expand to Uniswap V3
5. ⏳ Multi-pair aggregation

See [STAGE2_PLAN.md](../../STAGE2_PLAN.md) for full roadmap.
