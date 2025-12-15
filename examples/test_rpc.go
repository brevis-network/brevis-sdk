package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	// Read RPC URL from command line argument or environment variable
	rpcURL := os.Getenv("ETH_RPC_URL")
	if len(os.Args) > 1 {
		rpcURL = os.Args[1]
	}

	if rpcURL == "" {
		fmt.Println("Usage: go run test_rpc.go <RPC_URL>")
		fmt.Println("   or: ETH_RPC_URL=<url> go run test_rpc.go")
		os.Exit(1)
	}

	fmt.Printf("Testing RPC endpoint: %s\n\n", rpcURL)

	// Connect to RPC
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test 1: Get latest block number
	fmt.Println("Test 1: Getting latest block number...")
	blockNumber, err := client.BlockNumber(ctx)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Latest block: %d\n\n", blockNumber)

	// Test 2: Get USDC contract code
	fmt.Println("Test 2: Checking USDC contract...")
	usdcAddr := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	code, err := client.CodeAt(ctx, usdcAddr, nil)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ USDC contract exists (code length: %d bytes)\n\n", len(code))

	// Test 3: Get storage slot (USDC balance of a known holder)
	fmt.Println("Test 3: Reading storage slot...")
	// For a simple test, just read slot 0
	slot := common.Hash{}
	value, err := client.StorageAt(ctx, usdcAddr, slot, nil)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Storage read successful (value length: %d bytes)\n\n", len(value))

	// Test 4: Get a recent transaction
	fmt.Println("Test 4: Fetching recent block...")
	block, err := client.BlockByNumber(ctx, nil)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Block %d fetched (transactions: %d)\n\n", block.NumberU64(), len(block.Transactions()))

	fmt.Println("🎉 All RPC tests passed!")
	fmt.Println("\nYour RPC endpoint is working correctly and ready for circuit testing.")
}
