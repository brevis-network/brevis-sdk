# NFT Ownership Proof Circuit

## Overview

This circuit proves that a specific Ethereum address owns a specific NFT (ERC721 token) by verifying a Transfer event where the address received the NFT.

## Use Cases

- **Gated Communities**: Prove NFT ownership for access to exclusive content/events
- **Airdrops**: Verify NFT holdings for reward distribution
- **Governance**: Prove voting eligibility based on NFT ownership
- **Cross-Chain Verification**: Prove NFT ownership on L1 for L2 applications
- **Privacy-Preserving Verification**: Prove ownership without revealing full transaction history

## Circuit Logic

### Inputs (Circuit Parameters)
- `NFTContractAddr`: The ERC721 contract address
- `OwnerAddr`: The address claiming ownership
- `TokenID`: The specific NFT token ID being verified

### Data Source
Receipt logs containing ERC721 Transfer events

### Verification Steps
1. Extract the Transfer event from the transaction receipt
2. Verify the event is from the correct NFT contract
3. Verify the "to" address (recipient) matches the claimed owner
4. Verify the tokenId matches the claimed token
5. Ensure all fields are from the same log entry

### Outputs
- Owner address (verified)
- NFT contract address
- Token ID
- Block number of the transfer

## ERC721 Transfer Event Structure

```solidity
event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
```

**Event Topics:**
- `topics[0]`: Event signature hash `keccak256("Transfer(address,address,uint256)")`
- `topics[1]`: `from` address (sender)
- `topics[2]`: `to` address (recipient/owner)
- `topics[3]`: `tokenId`

## Running the Tests

### Prerequisites
1. Set up an Ethereum RPC endpoint (Infura, Alchemy, or local node)
2. Find a real NFT transfer transaction:
   - Go to Etherscan
   - Find an ERC721 contract (e.g., BAYC, CryptoPunks, etc.)
   - Look at the "Transfers" tab for a transfer event
   - Note the transaction hash, owner address, and token ID
3. Update test file with this information

### Example: Finding Test Data

For Bored Ape Yacht Club (BAYC):
1. Contract: `0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D`
2. Go to Etherscan: https://etherscan.io/address/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D
3. Click "Events" tab
4. Find a recent Transfer event
5. Note:
   - Transaction hash
   - "to" address (the new owner)
   - tokenId value

### Run Tests
```bash
cd examples/nftOwnership
go test -v
```

### Test Options
- `test.IsSolved()`: Fast constraint check (no proof generation)
- `test.ProverSucceeded()`: Full proof generation and verification (slower)

## Customization

### Change NFT Contract
To verify ownership of a different ERC721 collection:

```go
nftContract := common.HexToAddress("0xYOUR_NFT_CONTRACT_ADDRESS")
```

Popular NFT contracts:
- **BAYC**: `0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D`
- **CryptoPunks**: `0xb47e3cd837dDE78f449970b1fb1f8D7E9c8f8b3F` (Note: CryptoPunks uses different interface)
- **Azuki**: `0xED5AF388653567Af2F388E6224dC7C4b3241C544`
- **Doodles**: `0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e`

### Verify Multiple NFTs
To verify ownership of multiple NFTs, you can:
1. Modify `Allocate()` to accept more receipts
2. Use `AssertEach()` to verify each NFT
3. Loop through multiple token IDs

## Integration with Smart Contracts

After compiling and deploying this circuit, your Solidity contract can receive proofs:

```solidity
contract NFTOwnershipVerifier is BrevisApp {
    mapping(address => mapping(uint256 => bool)) public verifiedOwnership;

    function handleProofResult(
        bytes32 requestId,
        bytes32 vkHash,
        bytes calldata circuitOutput
    ) internal override {
        // Decode outputs
        address owner = address(uint160(uint256(bytes32(circuitOutput[0:32]))));
        address nftContract = address(uint160(uint256(bytes32(circuitOutput[32:64]))));
        uint256 tokenId = uint256(bytes32(circuitOutput[64:96]));
        uint64 blockNum = uint64(uint256(bytes32(circuitOutput[96:128])));

        // Mark as verified
        verifiedOwnership[owner][tokenId] = true;

        // Your application logic here
        // e.g., grant access, distribute rewards, etc.
        emit OwnershipVerified(owner, nftContract, tokenId, blockNum);
    }
}
```

## Limitations & Considerations

### Current Ownership vs. Historical Ownership
This circuit proves that the address **received** the NFT at some point. It does NOT prove current ownership because:
- The NFT might have been transferred away after the proven transfer
- For **current ownership**, you would need to:
  1. Prove the most recent transfer **to** the owner
  2. Prove there's no subsequent transfer **from** the owner
  3. Or use storage slot verification instead (checking `ownerOf[tokenId]`)

### Alternative Approach: Storage-Based Verification
For **current** ownership, consider using storage slots:
```go
// Read the ownerOf mapping from the NFT contract
// This proves current ownership at a specific block
ownerSlot := api.SlotOfStructFieldInMapping(OWNER_SLOT, 0, tokenIdBytes)
```

### Privacy Considerations
- This circuit reveals which NFT the user owns (contract + token ID)
- The block number reveals when they acquired it
- Consider use cases where this information disclosure is acceptable

## File Structure

```
nftOwnership/
├── circuit.go           # Main circuit implementation
├── circuit_test.go      # Test suite
└── README.md           # This file
```

## Advanced Features (Future Enhancements)

Potential improvements:
1. **Multiple NFT Verification**: Prove ownership of N NFTs from a collection
2. **Time-Based Ownership**: Prove ownership for a minimum duration
3. **Rarity Verification**: Combine with metadata to prove rarity traits
4. **Collection-Level Proof**: Prove holding ANY NFT from a collection (not specific ID)

## Next Steps

1. Find real NFT transfer data on Etherscan
2. Update test with actual transaction hash and parameters
3. Run tests with RPC endpoint
4. Compile the circuit for production use
5. Deploy a Solidity contract to receive proofs
6. Integrate into your dApp

## Resources

- [ERC721 Standard](https://eips.ethereum.org/EIPS/eip-721)
- [Etherscan](https://etherscan.io) - Find NFT transfer events
- [OpenSea](https://opensea.io) - Browse NFT collections
