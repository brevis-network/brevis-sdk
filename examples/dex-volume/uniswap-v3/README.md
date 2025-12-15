# Uniswap V3 Trading Volume Circuit

## Overview

This circuit proves trading volume on Uniswap V3 by analyzing Swap events.

**Status:** ✅ Compiles | ⚠️ Simplified implementation

**Key Challenge:** V3 uses signed integers (int256) for amounts, requiring special handling.

---

## V3 vs V2: Major Differences

| Feature | V2 | V3 |
|---------|----|----|
| Liquidity | Full range | Concentrated ranges |
| LP Tokens | Fungible | NFTs |
| Fee Tiers | 0.30% only | 0.05%, 0.30%, 1.00%, 0.01% |
| Amounts | uint256 (positive) | int256 (can be negative) ⚠️ |
| Capital Efficiency | 1x | Up to 4000x |

---

## Circuit Specification

### Inputs
```go
type AppCircuit struct {
    UserAddr  sdk.Uint248  // Trader address
    MinVolume sdk.Uint248  // Minimum volume
}
```

### Outputs
1. User address
2. Total volume (absolute value)
3. Minimum threshold
4. Swap count

---

## V3 Swap Event

```solidity
event Swap(
    address indexed sender,
    address indexed recipient,    // ← We verify this
    int256 amount0,               // Signed! Can be negative
    int256 amount1,               // ← We track this
    uint160 sqrtPriceX96,         // Current price
    uint128 liquidity,            // Active liquidity
    int24 tick                    // Current tick
);
```

**Signature:** `0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67`

---

## Signed Integer Challenge

### The Problem

**V2:** `amount1Out` is always positive (uint256)
**V3:** `amount1` can be positive OR negative (int256)

**Meaning:**
- Positive = tokens added to pool (user selling)
- Negative = tokens removed from pool (user buying)

### Our Simplified Solution

```go
// Current implementation: treats int256 as uint248
amount := api.ToUint248(r.Fields[0].Value)
```

**⚠️ Limitation:** Doesn't properly handle sign bit.

**Production needs:** Extract sign, convert two's complement to absolute value.

---

## Pool Addresses (Mainnet)

### USDC/WETH by Fee Tier

| Fee | Address | Usage |
|-----|---------|-------|
| 0.05% | `0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640` | Our circuit |
| 0.30% | `0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8` | Medium |
| 1.00% | `0x7BeA39867e4169DBe237d55C8242a8f2fcDcc387` | Lower |

---

## Circuit Logic

```
For each receipt:
  ✅ Verify pool = 0.05% USDC/WETH
  ✅ Verify event = V3 Swap
  ✅ Verify recipient = UserAddr
  ✅ Extract amount1 (simplified absolute value)

totalVolume = sum(amounts)
assert totalVolume >= MinVolume
```

---

## Compilation

✅ **Success**
```bash
cd examples/dex-volume/uniswap-v3
go build circuit.go
```

---

## Limitations

- ❌ Naive signed integer handling
- ❌ Single fee tier only (0.05%)
- ❌ Doesn't use sqrtPriceX96 or tick data
- ⏳ Production needs proper int256 handling

---

## V3 Concepts

### Concentrated Liquidity

**V2:** Liquidity spread 0 to ∞
**V3:** LPs choose price ranges (e.g., $1800-$2200)

**Result:** 4000x more capital efficient

### Tick System

Price = 1.0001^tick

- tick = 0 → price = 1.0
- tick = 10000 → price ≈ 2.718

### sqrtPriceX96

sqrt(price) * 2^96 (Q64.96 fixed-point format)

Enables efficient tick calculations.

---

## Related Circuits

- V2 Trading Volume (simpler, no signed integers)
- V3 LP Position Tracking (NFT-based)
- V3 Multi-Tier Aggregation (all fee tiers)
