// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

contract SmartBatcher {
    error CallFailed(bytes reason);

    enum Command {
        Call,
        StaticCall,
        SelfCall,
        MemoryCall,
        MemoryStaticCall,
        MemorySelfCall,
        Patch,
        Invalid
    }

    function smartBatch(bytes calldata commands, bytes[] calldata inputs) external payable {
        require(commands.length == inputs.length);
        bytes[] memory memoryData = new bytes[](inputs.length);
        for (uint256 i = 0 ; i < commands.length ; ) {
            uint8 command = uint8(commands[i]);
            // MemoryStaticCall
            if (command < 4) {
                if (command < 2) {
                    if (command < 1) {} else {}
                } else {
                    if (command < 3) {} else {}
                }
            } else {
                if (command < 6) {
                    if (command < 5) {} else {}
                } else {
                    if (command < 7) {
                        //(uint256 index, uint256 destOffset, uint256 offset, uint256 length) =
                        abi.decode(inputs[i], (uint256, uint256, uint256, uint256));
                    } else {
                        revert();
                    }
                }
            }
            unchecked { ++i; }
        }
    }

    enum CallOption {
        Call,
        StaticCall,
        SelfCall
    }

    struct Call {
        bytes32 command;
        bytes input;
    }

    address immutable SELF = address(this);

    function smartBatch(Call[] memory calls) external payable {
        bytes[] memory memData;
        bytes memory map;
        {
            uint256 length;
            (length, map) = _getAllocation(calls);
            memData = new bytes[](length);
        }
        for (uint256 i = 0 ; i < calls.length ; ) {
            (
                CallOption callOption,
                bool dismissRevert,
                uint256 out,
                uint256 value,
                address target
            ) = _decodeCommand(calls[i].command);
            require(out < calls.length);
            uint256 index;
            assembly ("memory-safe") {
                index := mload(add(add(map, 0x20), mul(i, 3)))
                index := sub(index, 1)
            }
            bytes memory result;
            if (index == 0) {
                result = _execute(
                    callOption,
                    dismissRevert, 
                    value,
                    target,
                    calls[i].input
                );
            } else {
                result = _execute(
                    callOption,
                    dismissRevert, 
                    value,
                    target,
                    memData[index]
                );
            }
            if (out > 0) {
                assembly ("memory-safe") {
                    index := mload(add(add(map, 0x20), mul(out, 3)))
                    index := sub(index, 1)
                }
                memData[index] = bytes.concat(calls[out].input, result);
            }
            unchecked { ++i; }
        }
    }

    function _execute(
        CallOption callOption,
        bool dismissRevert,
        uint256 value,
        address target,
        bytes memory data
    ) internal returns (bytes memory result) {
        bool success;
        if (callOption == CallOption.Call) {
            (success, result) = target.call{value : value}(data);
        } else if (callOption == CallOption.StaticCall) {
            (success, result) = target.staticcall(data);
        } else if (callOption == CallOption.SelfCall) {
            (success, result) = SELF.delegatecall(data);
        }
        if (!dismissRevert) require(success, CallFailed(result));
    }

    function _decodeCommand(bytes32 command) internal pure returns (
        CallOption callOption,
        bool dismissRevert,
        uint256 out,
        uint256 value,
        address target
    ) {
        assembly ("memory-safe") {
            callOption := byte(0, command)
            dismissRevert := and(shr(247, command), 1)
            out := shr(233, shl(9, command))
            value := shr(192, shl(32, command))
            target := and(command, 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function _getAllocation(Call[] memory calls) internal pure returns (
        uint256 length,
        bytes memory map
    ) {
        unchecked { map = new bytes(calls.length * 3); }
        uint256 index = 1;
        for (uint256 i = 0 ; i < calls.length ; ) {
            (,, uint256 out,,) = _decodeCommand(calls[i].command);
            if (out != 0) {
                assembly ("memory-safe") {
                    let offset := add(add(map, 0x20), mul(i, 3))
                    if iszero(mload(offset)) {
                        mstore(offset, index)
                        index := add(index, 1)
                        length := add(length, 1)
                    }
                }
            }
            unchecked { ++i; }
        }
    }
}
