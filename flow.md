# SDK Improvement Service Flow

```plantuml
TS -> Prover: prove(request)
TS <-- Prover: ProofResponse
TS -> Brevis: submit()
group submit(proof,srcChainId,dstChainId)
TS -> Brevis: prepareQuery(url, data...)
TS <-- Brevis: id, fee
TS -> Brevis: submitAppCircuitProof(url, proof)
TS <-- Brevis: success
loop wait until status is SUCCESS
TS -> Brevis: getQueryStatus(id)
TS <-- Brevis: status
end
```
