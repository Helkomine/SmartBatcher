// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;

bytes1 constant CALL = 0x00;
bytes1 constant STATICCALL = 0x01;
bytes1 constant SUBCALL = 0x02;
bytes1 constant OUTPUT = 0x03;

interface ISmartCall {
    function smartCall(bytes calldata commands, bytes[] calldata inputs) external payable returns (Output[] memory outputs);

    struct Output {
        bool success;
        bytes returnData;
    }
}

contract SmartCall is ISmartCall {
    address immutable SELF = address(this);

    error LengthMismatch();
    error CallAfter();
    error TooSoonIndex();
    error CopyOutOfRange();
    error InvalidBytesLengthToDecode(uint256 length);
    error InvalidCommand(bytes1 command);
    error NextIndexOutOfBound(uint256 index);
    error CallFailed(Output reason);
    error InvalidRange(uint256 start, uint256 end);

    function smartCall(bytes calldata commands, bytes[] calldata inputs) external payable returns (Output[] memory outputs) {
        _allocate(commands, inputs, outputs);
        uint256 callIndex;
        bytes[] memory runtimeInputs = new bytes[](inputs.length);
        for (uint256 i = 0 ; i < commands.length ; ) {
            bytes1 command = commands[i];
            if (command < SUBCALL) {
                if (command < STATICCALL) {
                    if (runtimeInputs[callIndex].length == 0) {
                        address target = address(bytes20(inputs[i][0 : 20]));
                        uint256 value = uint256(bytes32(inputs[i][20 : 52]));
                        bool allowFailure = inputs[i][52] != 0;
                        bytes calldata data = inputs[i][53 : ];
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = target.call{value : value}(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    } else {
                        bytes memory runtimeInput = runtimeInputs[callIndex];
                        address target;
                        uint256 value;
                        bool allowFailure = runtimeInput[52] != 0;
                        bytes memory data = _slice(53, runtimeInput.length, runtimeInput);
                        assembly ("memory-safe") {
                            let offset := add(runtimeInput, 0x20)
                            target := shr(96, mload(offset))
                            value := mload(add(offset, 20))
                        }
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = target.call{value : value}(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    }
                } else {
                    if (runtimeInputs[callIndex].length == 0) {
                        address target = address(bytes20(inputs[i][0 : 20]));
                        bool allowFailure = inputs[i][20] != 0;
                        bytes calldata data = inputs[i][21 : ];
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = target.staticcall(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    } else {
                        bytes memory runtimeInput = runtimeInputs[callIndex];
                        address target;
                        bool allowFailure = runtimeInput[20] != 0;
                        bytes memory data = _slice(21, runtimeInput.length, runtimeInput);
                        assembly ("memory-safe") {
                            let offset := add(runtimeInput, 0x20)
                            target := shr(96, mload(offset))
                        }
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = target.staticcall(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    }
                }
            } else {
                if (command < OUTPUT) {
                    if (runtimeInputs[callIndex].length == 0) {
                        bool allowFailure = inputs[i][0] != 0;
                        bytes calldata data = inputs[i][1 : ];
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = SELF.delegatecall(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    } else {
                        bytes memory runtimeInput = runtimeInputs[callIndex];
                        bool allowFailure = runtimeInput[0] != 0;
                        bytes memory data = _slice(1, runtimeInput.length, runtimeInput);
                        Output memory output = outputs[callIndex];
                        (output.success, output.returnData) = SELF.delegatecall(data);
                        if (allowFailure) require(output.success, CallFailed(output));
                        unchecked { ++callIndex; }
                    }
                } else {
                    bytes calldata input = inputs[i];
                    require(input.length % 32 == 0, InvalidBytesLengthToDecode(input.length));
                    uint256 nextIndex;
                    unchecked { nextIndex = i + 1; }
                    bytes memory runtimeInput = runtimeInputs[callIndex] = inputs[nextIndex];
                    for (uint256 j = 0 ; j < inputs[i].length ; ) {
                        unchecked {
                            uint256 word = uint256(bytes32(input[j : j + 32]));
                            uint256 index = word >> 192;
                            uint256 start = (word << 64) >> 192;
                            uint256 end = (word << 128) >> 192;
                            uint256 dest = word & type(uint64).max;
                            bytes memory output = outputs[index].returnData;
                            require(index < callIndex, TooSoonIndex());
                            require(start <= end, InvalidRange(start, end));
                            uint256 length = end - start;
                            require(dest + length <= runtimeInput.length, CopyOutOfRange());
                            assembly ("memory-safe") {
                                mcopy(add(add(runtimeInput, 0x20), dest), add(add(output, 0x20), start), length)
                            }
                            j += 32;
                        }
                    }
                }
            }
            unchecked { ++i; }
        }
    }

    function _allocate(bytes calldata commands, bytes[] calldata inputs, Output[] memory outputs) internal pure {
        require(commands.length == inputs.length, LengthMismatch());
        uint256 outputLength;
        unchecked {
            for (uint256 i = 0 ; i < commands.length ; ++i) {
                bytes1 command = commands[i];
                if (command < OUTPUT) ++outputLength;
                else if (command == OUTPUT)
                    if (i + 1 < commands.length) require(commands[i + 1] < OUTPUT, CallAfter());
                    else revert NextIndexOutOfBound(i + 1);
                else revert InvalidCommand(command);
            }
            outputs = new Output[](outputLength);
        }
    }

    function _slice(uint256 start, uint256 end, bytes memory input) internal pure returns (bytes memory output) {
        require(end <= input.length, "Slice out of bounds");
        uint256 length = end - start;
        assembly ("memory-safe") {
            output := mload(0x40)
            mstore(output, length)
            mcopy(add(output, 0x20), add(add(input, 0x20), start), length)
            mstore(0x40, add(add(output, 0x20), and(add(length, 0x1f), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        }
    }
}
