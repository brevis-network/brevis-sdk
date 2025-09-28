// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../../lib/BrevisAppZkOnly.sol";

contract TokenTransfer is BrevisAppZkOnly, Ownable {
    event TransferAmountAttested(uint64 blockNum, address account, uint256 volume);
    
    bytes32 public vkHash;
    
    constructor(address _brevisRequest) 
        BrevisAppZkOnly(_brevisRequest) 
        Ownable(msg.sender) 
    {}
    
    /**
     * @notice BrevisQuery contract will call our callback once Brevis backend submits the proof.
     * @dev This method is called once the proof is verified.
     * @param _vkHash The verifying key hash used by Brevis
     * @param _circuitOutput The output data from the circuit
     */
    function handleProofResult(
        bytes32 _vkHash, 
        bytes calldata _circuitOutput
    ) internal override {
        // Verify that the verifying key hash matches our designated key
        // This ensures the circuit output is authentic
        require(_vkHash == vkHash, "TokenTransfer: Invalid verifying key hash");
        
        (address accountAddr, uint64 blockNum, uint256 volume) = decodeOutput(_circuitOutput);
        
        emit TransferAmountAttested(blockNum, accountAddr, volume);
    }
    
    /**
     * @notice Decodes the circuit output into structured data
     * @param _output The raw circuit output bytes
     * @return userAddr The user address
     * @return blockNum The block number
     * @return volume The transfer volume
     */
    function decodeOutput(bytes calldata _output) 
        internal 
        pure 
        returns (address userAddr, uint64 blockNum, uint256 volume) 
    {
        blockNum = uint64(bytes8(_output[0:8]));
        userAddr = address(bytes20(_output[8:28]));
        volume = uint256(bytes32(_output[28:60]));
    }
    
    /**
     * @notice Sets the verifying key hash (only owner)
     * @param _newVkHash The new verifying key hash
     */
    function setVkHash(bytes32 _newVkHash) external onlyOwner {
        vkHash = _newVkHash;
    }
}
