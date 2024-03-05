# Brevis SDK

Please refer to [https://docs.brevis.network]() for the full documentation. 

This SDK aims to provide developers with a framework to implement custom data analysis computations and to interoperate with Brevis' provers.  

## Packages

- `github.com/brevis-network/brevis-sdk/sdk` Houses all things needed for writing custom circuits, compiling, proving, and interacting with brevis systems.
- `github.com/brevis-network/brevis-sdk/test` Contains testing utilities.

## Creating a Brevis App

`BrevisApp` is the entry point for most of the operations. To create a new app, use

```go
app := sdk.NewBrevisApp()
```

### Adding Data

The data that your circuit uses must be fed into the app before we can generate proofs.

```go
app.AddReceipt(sdk.ReceiptData{/*...*/})
app.AddStorage(sdk.StorageData{/*...*/})
app.AddTransaction(sdk.TransactionData{/*...*/})
```

### Defining Your Custom Circuit

```go
package app

import "github.com/brevis-network/brevis-sdk/sdk"

// AppCircuit must be a struct
type AppCircuit struct{
    // Custom inputs. These fields must be exported (first letter capitalized)
    // These are the inputs that can be different for each proof you generate
    // using the same circuit
    MyInput  sdk.Uint248
    MyInput2 sdk.Bytes32
}

func DefaultAppCircuit() *AppCircuit {
    return &AppCircuit{
        MyInput: sdk.ConstUint248(0),
        MyInput2: sdk.ConstBytes32([]byte{}),
    }
}

// the struct AppCircuit must implement the sdk.AppCircuit interface
var _ sdk.AppCircuit = &AppCircuit{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
    // When we return 1, 2, 3, it means that we are allowing our circuit to process 
    // a maximum of 1 receipts, 2 storages, and 3 transactions
    return 1, 2, 3
}

var ConstEventID = ParseEventID(/* 0x123456... */)

func (c *AppCircuit) Define(api *sdk.CircuitAPI, input sdk.DataInput) error {
    // You can access the data you added through app.AddReceipt etc.
    receipts := sdk.NewDataStream(api, input.Receipts)

    // Checking some the receipts properties against some constants
    // In this example, by checking these, you are proving to your 
    // contract that you have checked that all events have a certain
    // event ID
    sdk.AssertEach(receipts, func(receipt sdk.Receipt) Variable {
    return api.Equal(receipt.Fields[0].EventID, ConstEventID)
    })

    // You can then perform various data stream operations on the data. 
    // You can find the usage of specific API later.
    blockNums := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
    return r.BlockNum
    })
    minBlockNum := sdk.Min(blockNums)

    values := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
    return api.ToUint248(r.Value)
    })
    sum := sdk.Sum(values)

    // sdk.Reduce(...)
    // sdk.GroupBy(...)
    // and more ...

    // You can output any number of computation results using sdk.OutputXXX APIs 
    // These results will be available for use in your contract when the proof 
    // is verified on-chain 
    api.OutputUint(64, minBlockNum)
    api.OutputUint(248, sum)
    // more output...

    return nil
}
```

### Circuit Testing

```go
package app

import (
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
)

func TestAppCircuit(t *testing.T) {
    appCircuit := DefaultAppCircuit()
    appCircuitAssignment := &AppCircuit{
        MyInput: sdk.ConstUint248(123),
        MyInput2: sdk.ConstBytes32([]byte{0, 1, 2, 3}),
    }
    // BuildAppCircuit fetches additional data required to generate proofs from the
    // ETH RPC you provided and package the actual queried data into sdk.CircuitInput
    circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)

    // brevis-sdk/test package 

    // IsSolved is a quick way to check if your circuit can be solved using the given
    // inputs. This utility doesn't invoke the actual prover, so it's very fast. This
    // function is more useful when you want to quickly iterate and debug your
    // circuit logic.
    test.IsSolved(t, appCircuit, appCircuitAssignment, circuitInput)
    // ProverSucceeded is like IsSolved, but it internally goes through the entire
    // proving/verifying cycle. This function is favored for real testing. 
    test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
}
```

### Compiling Circuit

Your circuit needs to be compiled before you can generate a proof with it. sdk.Compile automatically downloads the SRS for your circuit size and saves a kzgsrs-bls12_377-xx file to the provided srsDir, then it compiles the circuit and saves the compiled circuit, poving key, and verifying key to outDir
```go
outDir := "$HOME/circuitOut/myapp"
srsDir := "$HOME/kzgsrs"

appCircuit := DefaultAppCircuit()
compiledCircuit, pk, vk, err := sdk.Compile(appCircuit, outDir, srsDir)
```

### Proving

```go
witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, circuitInput)
proof, err := sdk.Prove(ccs, pk, witness)
```

### Submitting Proof to Brevis

To submit your proof to Brevis, you first need to acquire a requestId and the fee amount using from Brevis using app.PrepareRequest, then submit the proof using app.SubmitProof.

```go
calldata, requestId, feeValue, err := app.PrepareRequest( vk, srcChainId, dstChainId, refundee, appContract)
err = app.SubmitProof(proof)
```

## Circuit API

The circuit API is a collection of math and logic operations that can be used when writing circuits. It also has a set of output methods that allows the user to output computation results to be used later in verifier. 

Please refer to [circuit_api.go](sdk/circuit_api.go) for the usage of each API. 

## Data Stream API

The data stream API gives the user the ability to perform various mapreduce styled aggregations on the source data.

To create an instance of the DataStream struct, use

```go
receipts := sdk.NewDataStream(api, input.Receipts)
```

Please refer to [datastream.go](sdk/datastream.go) for the usage of each API.

## Example App Circuits

[Examples App Circuits](examples)

You could also refer to these examples' test files to see more examples of sdk API usages. 
