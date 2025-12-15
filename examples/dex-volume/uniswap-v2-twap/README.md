# Uniswap V2 TWAP (Time-Weighted Average Price) Circuit

## Overview

This circuit proves time-weighted average prices from Uniswap V2 by reading cumulative price accumulators from pair contract storage.

**Status:** ✅ Compiles successfully | ⚠️ Simplified implementation

**Key Innovation:** Price oracle functionality using on-chain storage proofs.

---

## ⚠️ Important Limitations

This is a **simplified proof-of-concept** implementation due to SDK constraints:

**Current Implementation:**
- Reads 2 storage slots (price accumulators)
- Verifies sum of prices is within bounds
- Does NOT calculate true TWAP

**Production TWAP Requires:**
1. Access individual DataStream elements (currently not supported)
2. Calculate price delta (end - start)
3. Read block timestamps
4. Divide priceDelta by timeDelta
5. Handle UQ112.112 fixed-point format

**Use this circuit as:** Learning example, not production oracle.

---

## What is TWAP?

### Time-Weighted Average Price

**Formula:**
```
TWAP = (price1CumulativeLast[end] - price1CumulativeLast[start]) / (timestamp[end] - timestamp[start])
```

**Why TWAP?**
- Resistant to flash loan manipulation
- Smooth out price volatility
- Fair price for liquidations
- Standard DeFi oracle mechanism

---

## Uniswap V2 Price Accumulators

### Storage Layout

Uniswap V2 pairs store cumulative prices:

```solidity
contract UniswapV2Pair {
    uint public price0CumulativeLast;  // Slot 8
    uint public price1CumulativeLast;  // Slot 9
    uint public kLast;                 // Slot 10
}
```

**price0CumulativeLast:** Cumulative price of token0 (in token1 terms)
**price1CumulativeLast:** Cumulative price of token1 (in token0 terms)

These are updated on every swap with:
```solidity
price0CumulativeLast += price0 * timeElapsed;
price1CumulativeLast += price1 * timeElapsed;
```

---

## Circuit Specification

### Inputs
```go
type AppCircuit struct {
    PairAddr   sdk.Uint248  // Uniswap V2 pair
    MinPrice   sdk.Uint248  // Min price bound
    MaxPrice   sdk.Uint248  // Max price bound
    StartBlock sdk.Uint248  // TWAP start block
    EndBlock   sdk.Uint248  // TWAP end block
}
```

### Outputs
1. Pair address (verified)
2. Total cumulative prices (sum - simplified)
3. Minimum price threshold
4. Maximum price threshold
5. Block range

---

## Circuit Logic (Simplified)

```
Read storage slots:
  ✅ Slot 9 at StartBlock → price1CumulativeLast[start]
  ✅ Slot 9 at EndBlock   → price1CumulativeLast[end]

Verify:
  ✅ Contract = PairAddr
  ✅ Exactly 2 slots read
  ✅ Sum of prices within [MinPrice, MaxPrice]

Output:
  - Pair address
  - Total prices (start + end)
  - Bounds
  - Block range
```

**Note:** This doesn't calculate actual TWAP due to SDK limitations.

---

## Production TWAP Implementation

### What's Needed

```go
// Ideal implementation (not currently possible with SDK):

// 1. Read price accumulators
startPrice := readStorage(pair, slot9, startBlock)
endPrice := readStorage(pair, slot9, endBlock)

// 2. Read timestamps (not exposed in current SDK)
startTime := getBlockTimestamp(startBlock)
endTime := getBlockTimestamp(endBlock)

// 3. Calculate price delta
priceDelta := endPrice - startPrice

// 4. Calculate time delta
timeDelta := endTime - startTime

// 5. Calculate TWAP
twap := priceDelta / timeDelta

// 6. Verify bounds
assert(minPrice <= twap && twap <= maxPrice)
```

### SDK Gaps

- ❌ Can't access individual DataStream elements by index
- ❌ No block timestamp access in StorageSlot
- ❌ No Bytes32 comparison for slot verification
- ⏳ Future SDK updates may enable true TWAP

---

## UQ112.112 Format

Uniswap V2 uses **Q notation** for prices:

**Format:** UQ112.112 (unsigned, 112 integer bits, 112 fractional bits)

**Example:**
```
Raw value: 340282366920938463463374607431768211456
Actual price: value / (2^112) ≈ $2000 per ETH
```

**Why?** Maintains precision without floating point.

---

## Compilation

✅ **Success**
```bash
cd examples/dex-volume/uniswap-v2-twap
go build circuit.go  # Exit code: 0
```

---

## Use Cases (Future)

### When Production TWAP Works:

**1. Liquidation Price Oracle**
```
"WETH price via 1-hour TWAP is $1800?
 → Safe to liquidate underwater position"
```

**2. Fair Launch Pricing**
```
"24-hour TWAP is within ±5% of target?
 → Enable token transfers"
```

**3. Manipulation Resistance**
```
"Flash loan can't manipulate TWAP
 → Use for lending protocol oracle"
```

**4. Automated Market Operations**
```
"1-week TWAP crossed above $2000?
 → Trigger rebalancing"
```

---

## Current vs Future

| Feature | Current (Simplified) | Future (Production) |
|---------|---------------------|---------------------|
| Reads storage | ✅ Yes | ✅ Yes |
| Price delta | ❌ No | ✅ Yes |
| Time delta | ❌ No | ✅ Yes |
| True TWAP | ❌ No | ✅ Yes |
| UQ112.112 handling | ❌ No | ✅ Yes |
| Manipulation resistant | ❌ Limited | ✅ Yes |
| Production ready | ❌ No | ✅ Yes |

---

## Testing Requirements

### Storage Slot Reading

**Find test data:**
```bash
# Use eth_getStorageAt RPC call
curl -X POST \
  -H "Content-Type: application/json" \
  --data '{
    "jsonrpc":"2.0",
    "method":"eth_getStorageAt",
    "params":["0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc", "0x9", "latest"],
    "id":1
  }' \
  https://mainnet.infura.io/v3/YOUR_KEY
```

**Expected:** Large uint256 value (cumulative price)

---

## Why This Circuit Matters

### Learning Value

Even though simplified, this circuit demonstrates:

1. **Storage Slot Access** - Reading contract state
2. **Multi-Block Proofs** - Same slot at different blocks
3. **Price Oracles** - Foundation for TWAP
4. **SDK Limitations** - Understanding constraints
5. **Future Roadmap** - What's needed for production

### Pattern Foundation

Once SDK supports:
- Individual DataStream indexing
- Block timestamp access
- Bytes32 operations

This circuit can be upgraded to production TWAP with minimal changes.

---

## Related Circuits

- Token Balance Verification (storage slots - Stage 1)
- Uniswap V2 Trading Volume (receipts)
- Uniswap V3 TWAP (oracle contract)
- Chainlink Price Feed Verification (future)

---

## Differences from Trading Volume Circuits

| Aspect | Trading Volume | TWAP (This) |
|--------|---------------|-------------|
| Data Source | Receipt logs | Storage slots |
| Event Type | Swap | N/A |
| Aggregation | Sum amounts | Price delta / time |
| Blocks | Multiple txs | 2 specific blocks |
| Output | Total volume | Average price |
| Use Case | Activity proof | Price oracle |

---

## Production Upgrade Path

### Step 1: SDK Enhancement
Wait for SDK to support:
- DataStream element access by index
- Block metadata (timestamp)
- Bytes32 comparison

### Step 2: Circuit Update
```go
// Access individual elements
startPrice := prices[0]  // Currently not supported
endPrice := prices[1]    // Currently not supported

// Calculate delta
priceDelta := u248.Sub(endPrice, startPrice)

// Get timestamps (needs SDK support)
timeDelta := u248.Sub(endTimestamp, startTimestamp)

// True TWAP
twap := u248.Div(priceDelta, timeDelta)
```

### Step 3: UQ112.112 Handling
```go
// Decode fixed-point format
// price = rawValue / (2^112)
scaleFactor := u248.Const(1 << 112)
actualPrice := u248.Div(twap, scaleFactor)
```

---

## Achievement Unlocked

🎉 **First Storage-Based Oracle Circuit**

This demonstrates:
- ✅ Storage slot access (not just events)
- ✅ Multi-block state proofs
- ✅ Foundation for price oracles
- ✅ Identified SDK enhancement needs
- ✅ Clear upgrade path to production

**Pattern:** Storage proofs enable broader verification beyond transaction logs.

---

## Limitations Summary

**Current:**
- ⚠️ Simplified TWAP calculation (sum, not delta)
- ⚠️ No timestamp access
- ⚠️ No UQ112.112 decoding
- ⚠️ Limited slot verification

**Required for Production:**
- ⏳ DataStream indexing support
- ⏳ Block timestamp access
- ⏳ Bytes32 comparison
- ⏳ Fixed-point arithmetic helpers

**Status:** Proof of concept, not production ready.
