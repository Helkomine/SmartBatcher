// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

contract SmartBatcher {
    error LengthMismatch();
    error InvalidCommand(uint8 command);
    error CallFailed(bytes reason);

    address immutable SELF = address(this);

    bool transient executionActive;
    bool transient subCallEntry;

    modifier validateAccess() {
        if (!executionActive) {
            executionActive = true;
            _;
            executionActive = false;
        } else if (subCallEntry) {
            subCallEntry = false;
            _;
        }
    }

    function smartBatch(
        bytes calldata commands,
        bytes[] calldata inputs
    ) external payable validateAccess returns (bytes[] memory outputs) {
        unchecked {
            uint256 inputLength;
            uint256 outputLength;
            for (uint256 i = 0 ; i < commands.length ; ) {
                uint8 command = uint8(commands[i++]);
                if (command < 3) ++outputLength;
                else if (command < 5) ++inputLength;
            }
            require(inputs.length == inputLength, LengthMismatch());
            outputs = new bytes[](outputLength);
        }
        bytes memory memoryData;
        uint256 inputIndex;
        uint256 outputIndex;
        for (uint256 loop = 0 ; loop < commands.length ; ) {
            uint8 command = uint8(commands[loop]);
            unchecked { ++loop; }
            if (command < 4) {
                if (command < 2) {
                    // Call
                    if (command < 1) {
                        address target;
                        uint64 value;
                        bool required = (memoryData[28] != 0);
                        assembly ("memory-safe") {
                            let offset := add(memoryData, 0x20)
                            target := shr(96, mload(offset))
                            value := shr(192, mload(add(offset, 20)))
                        }
                        bool success;
                        (success, outputs[outputIndex]) = target.call{value : value}(_slice(29, memoryData.length, memoryData));
                        if (!required) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++outputIndex; }
                    // StaticCall
                    } else {
                        address target;
                        bool required = (memoryData[20] != 0);
                        assembly ("memory-safe") {
                            let offset := add(memoryData, 0x20)
                            target := shr(96, mload(offset))
                        }
                        bool success;
                        (success, outputs[outputIndex]) = target.staticcall((_slice(21, memoryData.length, memoryData)));
                        if (!required) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++outputIndex; }
                    }
                } else {
                    // SubCall
                    if (command < 3) {
                        bool required = (memoryData[0] != 0);
                        subCallEntry = true;
                        bool success;
                        (success, outputs[outputIndex]) = SELF.delegatecall((_slice(1, memoryData.length, memoryData)));
                        subCallEntry = false;
                        if (!required) require(success, CallFailed(outputs[outputIndex]));
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
                        bytes calldata input = inputs[inputIndex];
                        uint24 index = uint24(bytes3(input[0 : 3]));
                        uint24 start = uint24(bytes3(input[3 : 6]));
                        uint24 end = uint24(bytes3(input[6 : 9]));
                        if (start == end) {
                            start = 0;
                            end = uint24(outputs[index].length);
                        }
                        memoryData = bytes.concat(memoryData, _slice(start, end, outputs[index]));
                        unchecked { ++inputIndex; }
                    // Clear
                    } else memoryData = new bytes(0);
                } else revert InvalidCommand(command);
            }
        }
    }

    function _slice(uint256 start, uint256 end, bytes memory input) internal pure returns (bytes memory output) {
        require(end <= input.length, "Slice out of bounds");
        uint256 length = end - start;
        assembly ("memory-safe") {
            output := mload(0x40)
            mstore(output, length)
            mcopy(add(output, 0x20), add(add(input, 0x20), start), length)
            mstore(0x40, add(add(output, 0x20), and(add(length, 0x1f), not(0x1f))))
        }
    }

    receive() external payable {}
    fallback() external payable {}
}
