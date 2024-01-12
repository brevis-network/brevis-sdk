# Brevis SDK

This SDK aims to provide developers with a framework to implement custom data analysis computations and to interoperate with Brevis' provers.

## Concepts & Components

### Querier

Use `sdk.Querier` to query receipts, storage values, and transactions from regular Ethereum nodes. The querier can process the results into a `Witness object.

### Witness

The `sdk.Witness` object is basically the developer's circuit program input. It houses the list of queried receipts, storage values, and transactions.

### Host Circuit

The host circuit is a wrapper around the guest circuit. It handles several commitment steps required to interoperate with the proving system on Brevis' side.

### Guest Circuit

This is what the user of this SDK wants to implement their computation in. A guest circuit needs to conform to the `sdk.GuestCircuit` interface. The guest circuit is embedded into (is part of) the host circuit. 

### Circuit API

A set of circuit APIs for performing arithmetic calculations and logical operations over the native circuit variables. The user also must use the `OutputXXX()` methods to export their computation results.

### DataStream API

Provides a high level API for processing list data in guest circuit. The main goal of this API is to abstract away the hassle of handling variable-length lists in circuit from the user. 

## Data Types

### `sdk.Variable`

Variable of this type is native to our circuit's scalar field, and it requires to have a bit size of less than or equal to 248 bits as the guest/host circuit runs on BLS12 377 (can only represent numbers <= 252 bits). It can be used to represent anything from the solidity equivalent of boolean to uint248 or bytes31 

### `sdk.Bytes32`

Since a normal circuit variable can only represent numbers <= 252 bits, we cannot fit `bytes32` into it. But this type commonly used on ethereum in solidity code, we use the special types `Bytes32` to represent it in circuit. For now, there is no support for performing arithmetics over variables of this type, but the user can still do equality checks and conditional selection on them. If the user knows there is no way for the actual value of a `Bytes32` to overflow `uint248`, then they can use `api.ToVariable()` to cast it into a native circuit variable.

## Example Guest Circuits

[Examples](./circuits/sdk/examples)
