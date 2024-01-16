// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "../interface/IBrevisProof.sol";

abstract contract BrevisApp {
    IBrevisProof public immutable brevisProof;

    constructor(IBrevisProof _brevisProof) {
        brevisProof = _brevisProof;
    }

    function validateRequest(
        bytes32 _requestId,
        uint64 _chainId,
        Brevis.ExtractInfos memory _extractInfos
    ) public view virtual returns (bool) {
        brevisProof.validateRequest(_requestId, _chainId, _extractInfos);
        return true;
    }

    function callback(bytes32 _requestId, bytes calldata _appCircuitOutput) external {
        Brevis.ProofData memory proofData = IBrevisProof(brevisProof).getProofData(_requestId);
        require(proofData.appCommitHash == keccak256(_appCircuitOutput), "failed to open output commitment");
        handleProofResult(_requestId, proofData.appVkHash, _appCircuitOutput);
    }

    function handleProofResult(bytes32 _requestId, bytes32 _vkHash, bytes calldata _appCircuitOutput) internal virtual {
        // to be overrided by custom app
    }
}
