// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// App that accepts both ZK- and OP-attested results.
abstract contract BrevisApp {
    address public brevisRequest;

    struct BrevisOpConfig {
        uint64 challengeWindow;
        uint8 sigOption; // bitmap to express expected sigs: bit 0 is bvn, bit 1 is avs
    }
    // default: disable OP, require bvn sig
    BrevisOpConfig public brevisOpConfig = BrevisOpConfig(2 ** 64 - 1, 0x01);

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

    function handleOpProofResult(bytes32 _vkHash, bytes calldata _appCircuitOutput) internal virtual {
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

    function applyBrevisOpResult(
        bytes32 _proofId,
        uint64 _nonce,
        bytes32 _appVkHash,
        bytes32 _appCommitHash,
        bytes calldata _appCircuitOutput
    ) public {
        (uint256 challengeWindow, uint8 sigOption) = _getBrevisConfig();
        require(
            IBrevisRequest(brevisRequest).validateOpAppData(
                _proofId,
                _nonce,
                _appCommitHash,
                _appVkHash,
                challengeWindow,
                sigOption
            ),
            "data not ready to use"
        );
        require(_appCommitHash == keccak256(_appCircuitOutput), "invalid circuit output");
        handleOpProofResult(_appVkHash, _appCircuitOutput);
    }

    function applyBrevisOpResults(
        bytes32[] calldata _proofIds,
        uint64[] calldata _nonces,
        bytes32[] calldata _appVkHashes,
        bytes32[] calldata _appCommitHashes,
        bytes[] calldata _appCircuitOutputs
    ) external {
        (uint256 challengeWindow, uint8 sigOption) = _getBrevisConfig();
        require(
            IBrevisRequest(brevisRequest).validateOpAppData(
                _proofIds,
                _nonces,
                _appCommitHashes,
                _appVkHashes,
                challengeWindow,
                sigOption
            ),
            "data not ready to use"
        );
        for (uint256 i = 0; i < _proofIds.length; i++) {
            require(_appCommitHashes[i] == keccak256(_appCircuitOutputs[i]), "invalid circuit output");
            handleOpProofResult(_appVkHashes[i], _appCircuitOutputs[i]);
        }
    }

    function _getBrevisConfig() private view returns (uint256, uint8) {
        BrevisOpConfig memory config = brevisOpConfig;
        return (uint256(config.challengeWindow), config.sigOption);
    }
}

interface IBrevisRequest {
    function validateOpAppData(
        bytes32 _proofId,
        uint64 _nonce,
        bytes32 _appCommitHash,
        bytes32 _appVkHash,
        uint256 _appChallengeWindow,
        uint8 _option
    ) external view returns (bool);

    function validateOpAppData(
        bytes32[] calldata _proofIds,
        uint64[] calldata _nonces,
        bytes32[] calldata _appCommitHashes,
        bytes32[] calldata _appVkHashes,
        uint256 _appChallengeWindow,
        uint8 _option
    ) external view returns (bool);
}
