// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

contract SmartBatcher {
    error LengthMismatch();
    error InvalidCommand(uint8 command);
    error CallFailed(bytes reason);

    address immutable SELF = address(this);

    bool transient executionActive;
    bool transient selfCallEntry;

    modifier authenticationAccess() {
        if (!executionActive) {
            executionActive = true;
            _;
            executionActive = false;
        } else if (selfCallEntry) {
            selfCallEntry = false;
            _;
        }
    }

    function smartBatch(
        bytes calldata commands,
        bytes[] calldata inputs
    ) external payable authenticationAccess returns (bytes[] memory outputs) {
        unchecked {
            uint256 inputLength;
            uint256 outputLength;
            for (uint256 i = 0 ; i < commands.length ; ) {
                uint8 command = uint8(commands[i]);
                if (command < 3) ++outputLength;
                else if (command < 5) ++inputLength;
                ++i;
            }
            require(inputs.length == inputLength, LengthMismatch());
            outputs = new bytes[](outputLength);
        }
        bytes memory memoryData;
        uint256 inputIndex;
        uint256 outputIndex;
        for (uint256 loop = 0 ; loop < commands.length ; ) {
            uint8 command = uint8(commands[loop]);
            if (command < 4) {
                if (command < 2) {
                    // Call
                    if (command < 1) {
                        address target;
                        uint64 value;
                        bool dismissRevert;
                        assembly ("memory-safe") {
                            let offset := add(memoryData, 0x20)
                            target := shr(96, mload(offset))
                            value := shr(64, mload(add(offset, 20)))
                            dismissRevert := shr(248, mload(add(offset, 28)))
                        }
                        bool success;
                        (success, outputs[outputIndex]) = target.call{value : value}(_slice(29, memoryData.length, memoryData));
                        if (!dismissRevert) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++outputIndex; }
                    // StaticCall
                    } else {
                        address target;
                        bool dismissRevert;
                        assembly ("memory-safe") {
                            let offset := add(memoryData, 0x20)
                            target := shr(96, mload(offset))
                            dismissRevert := shr(248, mload(add(offset, 20)))
                        }
                        bool success;
                        (success, outputs[outputIndex]) = target.staticcall((_slice(21, memoryData.length, memoryData)));
                        if (!dismissRevert) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++outputIndex; }
                    }
                } else {
                    // SelfCall
                    if (command < 3) {
                        bool dismissRevert = (memoryData[0] != 0);
                        selfCallEntry = true;
                        bool success;
                        (success, outputs[outputIndex]) = SELF.delegatecall((_slice(1, memoryData.length, memoryData)));
                        selfCallEntry = false;
                        if (!dismissRevert) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++outputIndex; }
                    // Input
                    } else {
                        memoryData = bytes.concat(memoryData, inputs[inputIndex]);
                        unchecked { ++inputIndex; }
                    }
                }
            } else {
                if (command < 6) {
                    // Output
                    if (command < 5) {
                        uint24 index = uint24(bytes3(inputs[inputIndex][0 : 3]));
                        uint24 start = uint24(bytes3(inputs[inputIndex][3 : 6]));
                        uint24 end = uint24(bytes3(inputs[inputIndex][6 : 9]));
                        memoryData = bytes.concat(memoryData, _slice(start, end, outputs[index]));
                        unchecked { ++inputIndex; }
                    // Clear
                    } else memoryData = new bytes(0);
                } else revert InvalidCommand(command);
            }
            unchecked { ++loop; }
        }
    }

    function _slice(uint256 start, uint256 end, bytes memory input) internal pure returns (bytes memory output) {
        uint256 length = end - start;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            output := ptr
            mstore(output, length)
            mcopy(add(output, 0x20), add(add(input, 0x20), start), length)
            mstore(0x40, and(add(length, 31), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
        }
    }
}
