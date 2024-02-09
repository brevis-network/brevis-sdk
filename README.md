# Brevis SDK

This SDK aims to provide developers with a framework to implement custom data analysis computations and to interoperate with Brevis' provers.

## Packages

- `github.com/brevis-network/brevis-sdk/sdk` Houses all things needed for writing custom circuits, compiling, proving, and interacting with brevis systems.
- `github.com/brevis-network/brevis-sdk/test` Contains testing utilities.

## Creating a Brevis App

`BrevisApp` is the entry point for most of the operations. To create a new app, use

```go
app := sdk.NewBrevisApp("https://<eth-rpc-url>")
```

### Adding Data

The data that your circuit uses must be fed into the app before we can generate proofs.

```go
app.AddReceipt(sdk.ReceiptQuery{/*...*/})
app.AddStorage(sdk.StorageQuery{/*...*/})
app.AddTransaction(sdk.TransactionQuery{/*...*/})
```

### Defining Your Custom Circuit

```go
type AppCircuit struct{}

// the struct AppCircuit must implement the sdk.AppCircuit interface
var _ sdk.AppCircuit = &AppCircuit{} 

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
    // The returned values define the number of max receipt/storage/transaction count
    // your circuit is going to use. These are needed for optimization reasons. In
    // this example, your circuit can process a maximum of 1 receipt, 2 storages, and
    // 3 transactions
    return 1, 2, 3
}
func (c *AppCircuit) Define(api *sdk.CircuitAPI, input sdk.CircuitInput) error {
    // You can access the data you added through app.AddReceipt etc. in the `input` parameter 
    receipts := sdk.NewDataStream(api, input.Receipts)
	
    // You can then perform various data stream operations on the data. 
    // You can find the usage of specific API later.  
    sum := receipts
        .Map(/*...*/)
        .Reduce(/*...*/)
        .Sum(/*...*/)
    // ...
	
    // To output any computation results, use sdk.OutputXXX APIs 
    // These results will be available for use in your contract when   
    // the proof is verified on-chain 
    api.OutputUint(64, sum)
    // sdk.OutputBytes32(...)
    // and more..
    
    return nil
}
```

### Circuit Testing

```go
appCircuit := AppCircuit{}
appCircuitAssignment := AppCircuit{}
// BuildAppCircuit fetches additional data required to generate proofs from the
// ETH RPC you provided and package the actual queried data into sdk.CircuitInput
circuitInput, err := app.BuildCircuitInput(context.Background(), appCircuit)

// brevis-sdk/test package 

// IsSolved is a quick way to check if your circuit can be solved using the given
// inputs. This utility doesn't invoke the actual prover, so it's very fast. This
// function is more useful when you want to quickly iterate and debug your
// circuit logic.
test.IsSolved(t, appCircuit, appCircuitAssignment, circuitInput)
// ProverSucceeded is like IsSolved, but it internally goes through the entire
// proving/verifying cycle. This function is favored for real testing. 
test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
```

### Compiling Circuit

Compilation and setup are required for every new circuit. If you change your circuit logic or tweak the max counts defined in your `Allocate()` function, you need to recompile and setup  

The compilation output is the description of the circuit's constraint system. You should use sdk.WriteTo to serialize and save your circuit so that it can be used in the proving step later.

Setup is a one-time effort per circuit. A cache dir can be provided to output external dependencies. Once you have the verifying key you should also save its hash in your contract so that when a proof via Brevis is submitted on-chain you can verify that Brevis indeed used your verifying key to verify your circuit computations 

```go
outDir := "$HOME/circuitOut/age"
srsDir := "$HOME/kzgsrs"

appCircuit := AppCircuit{}
ccs, err := sdk.Compile(appCircuit, circuitInput)
pk, vk, err := sdk.Setup(ccs, srsDir)

// Save the outputs for use in proving steps later 
err = sdk.WriteTo(ccs, filepath.Join(outDir, "ccs"))
err = sdk.WriteTo(pk, filepath.Join(outDir, "pk"))
err = sdk.WriteTo(vk, filepath.Join(outDir, "vk"))
```

### Proving

```go
witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, circuitInput)
proof, err := sdk.Prove(ccs, pk, witness)
```

### Verifying

Verifying isn't really needed when using Brevis SDK. This utility function only exists to help developers get a sense of how a proof is verified.

```go
// returns error if verification fails
err := sdk.Verify(vk, publicWitness, proof)
```
## Circuit API

The circuit API is a collection of math and logic operations that can be used when writing circuits. It also has a set of output methods that allows the user to output computation results to be used later in verifier. 

Please refer to [circuit_api.go](sdk/circuit_api.go) for the usage of each API. 

## Data Stream API

The data stream API gives the user the ability to perform various mapreduce styled aggregations on the source data.

To create an instance of the DataStream struct, use

```go
receipts := sdk.NewDataStream(input.Receipts)
```

Please refer to [datastream.go](sdk/datastream.go) for the usage of each API.

## Example App Circuits

[Examples App Circuits](examples)

You could also refer to these examples' test files to see more examples of sdk API usages. 
