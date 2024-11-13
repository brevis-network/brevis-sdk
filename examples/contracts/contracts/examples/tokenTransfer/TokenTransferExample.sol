// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/access/Ownable.sol";

import "../../lib/BrevisAppZkOnly.sol";

contract TokenTransfer is BrevisAppZkOnly, Ownable {
    event TransferAmountAttested(uint64 blockNum, address account, uint256 volume);

    bytes32 public vkHash;

    constructor(address _brevisRequest) BrevisAppZkOnly(_brevisRequest) Ownable(msg.sender) {}

    // BrevisQuery contract will call our callback once Brevis backend submits the proof.
    // This method is called with once the proof is verified.
    function handleProofResult(bytes32 _vkHash, bytes calldata _circuitOutput) internal override {
        // We need to check if the verifying key that Brevis used to verify the proof
        // generated by our circuit is indeed our designated verifying key. This proves
        // that the _circuitOutput is authentic
        require(vkHash == _vkHash, "invalid vk");
        (address accountAddr, uint64 blockNum, uint256 volume) = decodeOutput(_circuitOutput);
        emit TransferAmountAttested(blockNum, accountAddr, volume);
    }


    function decodeOutput(bytes calldata o) internal pure returns (address, uint64, uint256) {
        uint64 blockNum = uint64(bytes8(o[0:8]));
        address userAddr = address(bytes20(o[8:28]));
        uint256 volume = uint256(bytes32(o[28:60]));
        return (userAddr, blockNum, volume);
    }

    function setVkHash(bytes32 _vkHash) external onlyOwner {
        vkHash = _vkHash;
    }
}
