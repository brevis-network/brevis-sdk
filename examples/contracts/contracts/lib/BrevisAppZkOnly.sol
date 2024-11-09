// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// App that only accepts ZK-attested results.
abstract contract BrevisAppZkOnly {
    address public brevisRequest;

    modifier onlyBrevisRequest() {
        require(msg.sender == brevisRequest, "invalid caller");
        _;
    }

    constructor(address _brevisRequest) {
        brevisRequest = _brevisRequest;
    }

    function handleProofResult(bytes32 _vkHash, bytes calldata _appCircuitOutput) internal virtual {
        // to be overrided by custom app
    }

    function brevisCallback(bytes32 _appVkHash, bytes calldata _appCircuitOutput) external onlyBrevisRequest {
        handleProofResult(_appVkHash, _appCircuitOutput);
    }

    function brevisBatchCallback(
        bytes32[] calldata _appVkHashes,
        bytes[] calldata _appCircuitOutputs
    ) external onlyBrevisRequest {
        for (uint i = 0; i < _appVkHashes.length; i++) {
            handleProofResult(_appVkHashes[i], _appCircuitOutputs[i]);
        }
    }
}
