# SushiSwap Liquidity Provider Tracking Circuit

## Overview

This circuit proves that a user provided liquidity to a SushiSwap pair by analyzing **Mint events** (not Swap events).

**Key Fact:** SushiSwap is a Uniswap V2 fork with identical Mint event structure.

**Status:** ✅ Compiles successfully | ⏳ Awaiting gateway for testing

---

## Key Difference: LP vs Trading

| Aspect | This Circuit (LP) | Trading Volume Circuit |
|--------|------------------|----------------------|
| Event Type | Mint | Swap |
| User Action | Add liquidity | Trade tokens |
| Proves | Token deposits into pool | Token swaps through pool |
| Use Case | Reward LPs | Reward traders |

---

## Circuit Specification

### Inputs
```go
type AppCircuit struct {
    UserAddr       sdk.Uint248  // LP address
    MinLiquidityV0 sdk.Uint248  // Min token0 (USDC)
    MinLiquidityV1 sdk.Uint248  // Min token1 (WETH)
}
```

### Outputs
1. User address (verified LP)
2. Total token0 provided (USDC)
3. Total token1 provided (WETH)
4. Number of liquidity additions

---

## Mint Event Structure

```solidity
event Mint(
    address indexed sender,  // Who added liquidity
    uint amount0,            // Token0 amount
    uint amount1             // Token1 amount
);
```

**Signature:** `0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f`

**Field Mapping:**
- Field[0]: `sender` (topic 1, indexed)
- Field[1]: `amount0` (data 0, USDC)
- Field[2]: `amount1` (data 1, WETH)

---

## Use Cases

1. **LP Airdrops** - "Provided ≥ 1000 USDC + 0.5 WETH liquidity? Claim tokens"
2. **LP NFT Badges** - "Added liquidity ≥ 5 times? Get LP NFT"
3. **Governance Weight** - Vote weight based on cumulative liquidity
4. **Fee Discounts** - Lower trading fees for active LPs

---

## Circuit Logic

```
For each Mint receipt:
  ✅ Verify contract = USDC/WETH pair
  ✅ Verify event = Mint signature
  ✅ Verify sender = UserAddr
  ✅ Extract amount0 (USDC)
  ✅ Extract amount1 (WETH)

totalUSDC = sum(all amount0)
totalWETH = sum(all amount1)

assert totalUSDC >= MinLiquidityV0
assert totalWETH >= MinLiquidityV1
```

---

## Compilation

✅ **Success**
```bash
cd examples/dex-volume/uniswap-v2-lp
go build circuit.go  # Exit code: 0
```

---

## Limitations

- ❌ Doesn't track liquidity removal (Burn events)
- ❌ Doesn't prove duration (how long LP stayed in pool)
- ❌ Doesn't check current LP token balance
- ⏳ Future: Add Burn tracking for net position

---

## Related Circuits

- Uniswap V2 LP Tracking (same logic, different pair)
- SushiSwap Trading Volume (Swap events)
- LP Duration Proof (Mint + Burn with time bounds)
- Impermanent Loss Calculator

---

## SushiSwap Pair Address

**USDC/WETH:** `0x397FF1542f962076d0BFE58eA045FfA2d347ACa0`

This is the ONLY difference from Uniswap V2 LP circuit - everything else is 100% identical.
