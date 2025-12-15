# Token Holder Verification Circuit

## Overview

This circuit proves that a specific Ethereum address holds at least a minimum amount of a specific ERC20 token (USDC in this example) at a given block height.

## Use Cases

- **Airdrop Eligibility**: Prove token holdings without revealing exact balance
- **Gated Access**: Verify minimum token balance for access control
- **Governance**: Verify voting power based on token holdings at snapshot block
- **Loyalty Programs**: Prove long-term holding without exposing wallet history

## Circuit Logic

### Inputs
- `HolderAddr` (circuit parameter): The Ethereum address to verify
- Storage slot data from blockchain (fetched via RPC)

### Constants
- `USDCTokenAddr`: USDC contract address on Ethereum mainnet
- `minimumBalance`: Minimum required balance (100 USDC = 100 * 10^6)

### Verification Steps
1. Verify the storage slot belongs to the USDC contract
2. Calculate the correct storage slot for `balanceOf[holderAddress]`
3. Verify we're reading the correct storage slot
4. Extract the balance value
5. Assert balance ≥ minimum threshold

### Outputs
- Holder address (verified)
- Actual balance at the block
- Block number of verification

## Storage Slot Calculation

For USDC, the `balanceOf` mapping is at storage slot **9**.

```solidity
// USDC contract (simplified)
mapping(address => uint256) public balanceOf; // slot 9
```

The storage key is calculated as:
```
slot_key = keccak256(abi.encode(holderAddress, 9))
```

## Running the Tests

### Prerequisites
1. Set up an Ethereum RPC endpoint (Infura, Alchemy, or local node)
2. Update `rpc` variable in `circuit_test.go` with your RPC URL
3. Update `holderAddress` with an address that holds ≥100 USDC
4. Update `BlockNum` with a recent block number

### Run Tests
```bash
cd examples/tokenHolder
go test -v
```

### Test Options
- `test.IsSolved()`: Fast constraint check (no proof generation)
- `test.ProverSucceeded()`: Full proof generation and verification (slower)

## Customization

### Change Token
To verify holdings of a different ERC20 token:

1. Update `USDCTokenAddr` with the new token contract address
2. Find the storage slot for `balanceOf` mapping (may differ from slot 9)
   - Check the token's contract source code
   - Or use storage analysis tools
3. Update `minimumBalance` based on token decimals

### Change Threshold
To change the minimum balance requirement:
```go
var minimumBalance = sdk.ConstUint248(YOUR_AMOUNT) // in token's smallest unit
```

Example for different tokens:
- USDC (6 decimals): `1000 USDC = 1000000000` (1000 * 10^6)
- DAI (18 decimals): `100 DAI = 100000000000000000000` (100 * 10^18)
- USDT (6 decimals): `500 USDT = 500000000` (500 * 10^6)

## Integration with Smart Contracts

After compiling and deploying this circuit, your Solidity contract can receive proofs:

```solidity
contract TokenHolderVerifier is BrevisApp {
    function handleProofResult(
        bytes32 requestId,
        bytes32 vkHash,
        bytes calldata circuitOutput
    ) internal override {
        // Decode outputs
        address holderAddr = address(uint160(uint256(bytes32(circuitOutput[0:32]))));
        uint248 balance = uint248(uint256(bytes32(circuitOutput[32:64])));
        uint64 blockNum = uint64(uint256(bytes32(circuitOutput[64:96])));

        // Your application logic here
        // e.g., grant access, distribute rewards, etc.
    }
}
```

## File Structure

```
tokenHolder/
├── circuit.go           # Main circuit implementation
├── circuit_test.go      # Test suite
└── README.md           # This file
```

## Notes

- **USDC storage slot**: The `balanceOf` mapping is at slot 9 (verified from USDC contract)
- **Block number**: Use historical blocks for verifiable snapshots
- **Gas efficiency**: Storage proofs are more efficient than receipt proofs for balance checks
- **Privacy**: Only proves balance ≥ threshold, doesn't reveal exact amount (unless output explicitly shows it)

## Next Steps

1. Test with real data using an RPC endpoint
2. Compile the circuit for production use
3. Deploy a Solidity contract to receive proofs
4. Integrate into your dApp
