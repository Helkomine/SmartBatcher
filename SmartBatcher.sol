// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

contract SmartBatcher {
    error CallFailed(bytes reason);
    error InvalidCommand(uint8 command);

    address immutable SELF = address(this);

    function smartBatch(
        bytes calldata commands,
        bytes[] calldata inputs
    ) external payable returns (bytes[] memory outputs) {
        require(commands.length == inputs.length);
        outputs = new bytes[](_getAllocate(commands));
        bytes memory memoryData;
        for (uint256 i = 0 ; i < commands.length ; ) {
            bool success;
            uint8 command = uint8(commands[i]);
            bytes calldata input = inputs[i];
            if (command < 4) {
                if (command < 2) {
                    // Call
                    if (command < 1) {
                        address target = address(bytes20(input[0 : 20]));
                        uint64 value = uint64(bytes8(input[20 : 28]));
                        bool dismissRevert = input[28] != 0;
                        (success, outputs[i]) = target.call{value : value}(memoryData);
                        if (!dismissRevert) require(success, CallFailed(outputs[i]));
                    // StaticCall
                    } else {
                        address target = address(bytes20(input[0 : 20]));
                        bool dismissRevert = input[20] != 0;
                        (success, outputs[i]) = target.staticcall(memoryData);
                        if (!dismissRevert) require(success, CallFailed(outputs[i]));
                    }
                } else {
                    // SelfCall
                    if (command < 3) {
                        bool dismissRevert = input[0] != 0;
                        (success, outputs[i]) = SELF.delegatecall(memoryData);
                        if (!dismissRevert) require(success, CallFailed(outputs[i]));
                    // ConcatCalldata
                    } else memoryData = bytes.concat(memoryData, input);
                }
            } else {
                if (command < 6) {
                    // ConcatOutput
                    if (command < 5) {
                        uint32 index = uint32(bytes4(input[0 : 4]));
                        uint64 start = uint64(bytes8(input[4 : 12]));
                        uint64 end = uint64(bytes8(input[12 : 20]));
                        memoryData = bytes.concat(memoryData, _concatBySlice(start, end, outputs[index]));
                    // Clear
                    } else memoryData = new bytes(0);
                } else revert InvalidCommand(command);
            }
            unchecked { ++i; }
        }
    }

    function _concatBySlice(
        uint256 start,
        uint256 end,
        bytes memory input
    ) internal pure returns (bytes memory output) {
        uint256 length = end - start;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            output := ptr
            mstore(output, length)
            mcopy(add(output, 0x20), add(add(input, 0x20), start), length)
            mstore(0x40, and(add(length, 31), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
        }
    }

    function _getAllocate(bytes calldata commands) internal pure returns (uint256 length) {
        for (uint256 i = 0 ; i < commands.length ; ) {
            unchecked {
                if (uint8(commands[i]) < 3) ++length;
                ++i;
            }
        }
    }
}
