
# SDK Improvement Plan Draft

## Use Case

This change is specifically talored to meet pancake's requirements. The goal is to further minimize Go code written by the devs, and remove all ZK concepts.

The high-level components are:

User -> Pancake server -> (Typescript SDK) -> Prover services

Pancake server handles user requests, request status tracking, data fetching, and other pancake's business logics

"Total Fee" and "Rewards" are two separate prover services

## New SDK Feature: Prover Service

In Brevis SDK, add the ability to start a prover service (that hosts a set of API that interacts with the Typescript SDK) for any app circuit built with the SDK.

The service should integrate tightly with the Typescript SDK which the devs can use in their TS server. There should be no scenario that a dev needs to call this service's API directly. All interactions are handled by the TS SDK.

Even though this plan still requires the user to write some Go, it is extremely minimal as the user no longer need to care about any ZK concepts. No compilation, no setup, no proving/verifying keys. They still do need to care about the VK hash and set it in their contract because it's too security-critical. The VK hash is printed every time the user restarts the program. They can also find it in their configured `ProverConfig.OutputDir`.

```go
// Developer's go code
var serviceName = flag.String("service", "", "the name of the service to start")
var port = flag.String("port", "22353", "the port to start the service at")

func main() {
    flag.Parse()

    if len(*serviceName) == 0 {
        panic("flag -service is required")
    }
    if len(*port) == 0 {
        panic("flag -port is required")
    }

    switch *serviceName {
    case "totalFee":
        startService(app.TotalFeeCircuit{})
    case "reward":
        startService(app.RewardCircuit{})
    default:
        panic("invalid -service flag")
    }
}

func startService(app sdk.AppCircuit) {
    config := ProverConfig {
        SrsDir: "$HOME/srsDir",
        OutputDir: "$HOME/circuitOut",
    }

    // Prover service manages circuit compilation/setup, and the proving/verifying keys. 
    // It automatically runs setup for the circuit if the circuit has not been set up before or if the circuit digest changes.
    service, err := sdk.NewProverService(app, config)
    if err != nil {
        panic(err)
    }

    err := service.Start(*port)
    if err != nil {
        panic(err)
    }
}
```
```sh
# The shell commands that a developer would run

# The template project includes a Makefile (which nodejs devs can easily understand as it's almost a 1-to-1 mapping of npm script. Though, it requires the developer to install the 'make' binary)

# Runs the tests under app/
make test

# Builds the project and install it as $HOME/go/bin/prover
make install

# User the prover binary to start up the services
prover -service=totalFee

prover -service=reward
```

## NewTypescript SDK

The Typescript SDK is a library that allows the user to integrate with both Brevis backend and their prover serivces with minimal surface area.

### Installing the Typescript SDK

```shell
yarn add "brevis-sdk"
```

### Using the Typescript SDK

```ts
import brevis from "brevis-sdk"

const provers = {
    totalFee: "localhost:22353",
    rewards: "localhost:22354"
}

const request = brevis.newProofRequest(provers.rewards)
// add transaction/receipt/storage is the same as the Go SDK
request.addStorage({
    blockNum: "123456",
    address: "0x1234",
    key: "0x1234",
    value: "0x1234",
});
// receipt.addStorage() ...add more storage data

// this corresponds to the custom inputs of the circuit
request.addCustomInput({
    userAddress: "0x1234",
    tokenId: ["0x0000", "0x1111"],
    token0TotalFees: ["1234578", "12345678"],
    token1TotalFees: ["1234578", "12345678"],
});

request.onError((id, err) => {
    // the data to prove doesn't meet the requirement (e.g. tx size larger than limit...)
    if (err.isNonRetryable()) {
        // ... mark something as failed
        return
    }
    // ... handle retryable errors
});

request.onProofGenerated((id, proof) => {
    console.log(id, proof.data)
    // ...
});

request.onRequestFulfilled((id, tx) => {
    console.log(id, tx)
    // ...
});

// request.execute() internally does:
// 1. interact with the configured app prover to get the app proof
// 2. interact with Brevis backend to submit the app proof
// the supplied <optional-custom-id> can be accessed in all request.onXXX callbacks 
await request.execute("<optional-custom-id>")
```
