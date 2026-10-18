// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

/*
*call
entry/postCheck/exit
keep/take/slice
balance/word
lt/gt/eq/in
add/sub/mul/div/ratio
smart flash loan
rLt/rGt/rEq/rIn
rAdd/rSub/rMul/rDiv
mode:
static:
forbid postCheck/exit, keep/take
runtime:
forbid nested entry/postCheck, *call
scan before run
*/
contract SmartBatcher {
    error LengthMismatch();
    error InvalidSubFrame();
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
                else ++inputLength;
            }
            require(inputs.length == inputLength, LengthMismatch());
            outputs = new bytes[](outputLength);
        }
        bytes memory memoryData;
        uint256 inputIndex;
        uint256 outputIndex;
        bool useOutput;
        for (uint256 loop = 0 ; loop < commands.length ; ) {
            uint8 command = uint8(commands[loop]);
            unchecked { ++loop; }
            if (command < 4) {
                if (command < 2) {
                    // Call
                    if (command < 1) {
                        bool success;
                        bool required;
                        if (useOutput) {
                            useOutput = false;
                            address target;
                            uint256 value;
                            required = memoryData[52] != 0;
                            assembly ("memory-safe") {
                                let offset := add(memoryData, 0x20)
                                target := shr(96, mload(offset))
                                value := mload(add(offset, 20))
                            }
                            (success, outputs[outputIndex]) = target.call{value : value}(_slice(53, memoryData.length, memoryData));
                        } else {
                            bytes calldata input = inputs[inputIndex];
                            address target = address(bytes20(input[0 : 20]));
                            uint256 value = uint256(bytes32(input[20 : 52]));
                            required = input[52] != 0;
                            (success, outputs[outputIndex]) = target.call{value : value}(input[53 : ]);
                        }
                        if (!required) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++inputIndex; }
                        unchecked { ++outputIndex; }
                    // StaticCall
                    } else {
                        bool success;
                        bool required;
                        if (loop > 0 && useOutput) {
                            useOutput = false;
                            address target;
                            required = (memoryData[20] != 0);
                            assembly ("memory-safe") {
                                let offset := add(memoryData, 0x20)
                                target := shr(96, mload(offset))
                            }
                            (success, outputs[outputIndex]) = target.staticcall((_slice(21, memoryData.length, memoryData)));
                        } else {
                            bytes calldata input = inputs[inputIndex];
                            address target = address(bytes20(input[0 : 20]));
                            required = input[21] != 0;
                            (success, outputs[outputIndex]) = target.staticcall(input[21 : ]);
                        }
                        if (!required) require(success, CallFailed(outputs[outputIndex]));
                        unchecked { ++inputIndex; }
                        unchecked { ++outputIndex; }
                    }
                } else {
                    // SubCall
                    if (command < 3) {
                        bool success;
                        bool required;
                        if (loop > 0 && useOutput) {
                            useOutput = false;
                            required = (memoryData[0] != 0);
                            subCallEntry = true;
                            (success, outputs[outputIndex]) = SELF.delegatecall((_slice(1, memoryData.length, memoryData)));
                            if (!required) require(success, CallFailed(outputs[outputIndex]));
                            subCallEntry = false;
                        } else {
                            bytes calldata input = inputs[inputIndex];
                            required = input[0] != 0;
                            subCallEntry = true;
                            (success, outputs[outputIndex]) = SELF.delegatecall(input[1 : ]);
                            if (!required) require(success, CallFailed(outputs[outputIndex]));
                            subCallEntry = false;
                        }
                        require(outputs[outputIndex].length > 0, InvalidSubFrame());
                        unchecked { ++inputIndex; }
                        unchecked { ++outputIndex; }
                    // Output
                    } else {
                        unchecked {
                            uint8 nextCommand = uint8(commands[loop + 1]);
                            require(nextCommand < 3);
                        }
                        useOutput = true;
                        bytes calldata input = inputs[inputIndex];
                        unchecked { ++inputIndex; }
                        require(input.length & 32 == 0);
                        for (uint256 i = 0 ; i < input.length >> 5 ; ) {
                            uint24 index = uint24(bytes3(input[0 : 3]));
                            uint24 start = uint24(bytes3(input[3 : 6]));
                            uint24 end = uint24(bytes3(input[6 : 9]));
                            if (start == end) {
                                start = 0;
                                end = uint24(outputs[index].length);
                            }
                            assembly ("memory-safe") {}
                        }
                        //memoryData = bytes.concat(memoryData, _slice(start, end, outputs[index]));
                    }
                }
            } else {
                if (command < 6) {
                    // Output
                    if (command < 5) {
                    }
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
