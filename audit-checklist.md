# Brevis SDK Audit Check List

1. Fix dummy input commitment: commit `a40b3c118398d6e5d578c4ae3f48bf47a425075d`, change files: `sdk/app.go`
2. Add `MptKeyPath` to the inputs for transaction, and add `LogPos` to receipt inputs. commit: `14327a2c7941cf32bb7243db82787d837b0d8aa1`, change files: `sdk/circuit_input.go`
3. Fix value assignment for `LogPos` and `MptKeyPath`. Change dummy input commitment for `LogPos` and `MptKeypath`. commit: `7c73fc137908aac63e7c39320dee358c4b8ca9cf`, change files: `sdk/app.go`, `sdk/circuit_input.go` and `common/const.go`
4. Fix ToUint521 for Uint48. Changed files: `sdk/circuit_api.go`, `sdk/api_uint521_test.go`
5. Add default commitment. Then all the sdk proof will have a commitment, no matter use assertUniq or not. change files: `sdk/host_circuit.go` [PR 16](https://github.com/brevis-network/brevis-sdk/pull/16)
6. Fix reading circuit input after changing curve to BN254. Changed files: `sdk/periphery.go`
7. Add digest tool to calculate application vk hash for developer. change file: `sdk/circuit_digest_tool,go` [PR-17](https://github.com/brevis-network/brevis-sdk/pull/17)
8. Add Keccak256 API. [PR-24](https://github.com/brevis-network/brevis-sdk/pull/24), change files: `sdk/circuit_api.go`.
9. Fix plonk bn254 vk hash, change files: `common/utils/plonk_util.go`.