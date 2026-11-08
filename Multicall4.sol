// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

interface IMulticall4 {
    enum Route {
        RAW,
        OUTPUT
    }

    enum Operation {
        CALL,
        STATICCALL,
        SELFCALL
    }

    struct Target {
        Route route;
        bytes32 input;
    }

    struct Value {
        Route route;
        bytes32 input;
    }

    struct Required {
        Route route;
        bytes32 input;
    }

    struct InputData {
        Route route;
        bytes input;
    }

    struct Data {
        Operation operation;
        InputData[] inputData;
    }

    struct Batch {
        Target target;
        Value value;
        Required required;
        Data data;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    error InvalidIndex(uint64 index);
    error CallFailed(bytes reason);

    function multicall(Batch[] calldata batches) external payable returns (Result[] memory results);
}

abstract contract Multicall4 is IMulticall4 {
    uint64 constant SENTINEL = 1;

    address immutable SELF = address(this);

    function multicall(Batch[] calldata batches) external payable returns (Result[] memory results) {
        results = new Result[](batches.length);
        for (uint256 i = 0 ; i < batches.length ; ) {
            Batch calldata batch = batches[i];
            address target;
            if (batch.target.route == Route.RAW) target = address(bytes20(batch.target.input));
            else {
                bytes32 _input = batch.target.input;
                uint64 index = uint64(uint256(_input) >> 192);
                uint64 start = uint64((uint256(_input) << 64) >> 192);
                require(index < i, InvalidIndex(index));
                Result memory _result = results[index];
                target = address(bytes20(_slice(_result.returnData, start, start + 20)));
            }
            uint256 value;
            if (batch.value.route == Route.RAW) value = uint256(batch.value.input);
            else {
                bytes32 _input = batch.value.input;
                uint64 index = uint64(uint256(_input) >> 192);
                uint64 start = uint64((uint256(_input) << 64) >> 192);
                require(index < i, InvalidIndex(index));
                Result memory _result = results[index];
                value = uint256(bytes32(_slice(_result.returnData, start, start + 32)));
            }
            bool required;
            if (batch.required.route == Route.RAW) required = (batch.required.input != 0);
            else {
                bytes32 _input = batch.required.input;
                uint64 index = uint64(uint256(_input) >> 192);
                uint64 start = uint64((uint256(_input) << 64) >> 192);
                require(index < i, InvalidIndex(index));
                Result memory _result = results[index];
                required = (_result.returnData[start] != 0);
            }
            bytes memory data;
            for (uint256 j = 0 ; j < batch.data.inputData.length ; ) {
                InputData calldata _data = batch.data.inputData[j];
                if (_data.route == Route.RAW) data = bytes.concat(data, _data.input);
                else {
                    bytes32 _input = bytes32(_data.input);
                    uint64 index = uint64(uint256(_input) >> 192);
                    uint64 start = uint64((uint256(_input) << 64) >> 192);
                    uint64 end = uint64((uint256(_input) << 128) >> 192);
                    uint64 sentinel = uint64(uint256(_input) & SENTINEL);
                    require(index < i, InvalidIndex(index));
                    Result memory _result = results[index];
                    if (sentinel != SENTINEL) data = bytes.concat(data, _slice(_result.returnData, start, end));
                    else data = bytes.concat(data, _slice(_result.returnData, start, _result.returnData.length - end));
                }
                unchecked { ++j; }
            }
            Result memory result = results[i];
            if (batch.data.operation == Operation.CALL) (result.success, result.returnData) = target.call{value : value}(data);
            else if (batch.data.operation == Operation.STATICCALL) (result.success, result.returnData) = target.staticcall(data);
            else (result.success, result.returnData) = SELF.delegatecall(data);
            if (!required) require(result.success, CallFailed(result.returnData));
            unchecked { ++i; }
        }
    }

    error InvalidOutputRange();
    function _slice(
        bytes memory source,
        uint256 start,
        uint256 end
    ) private pure returns (
        bytes memory result
    ) {
        if (start > end || end > source.length) revert InvalidOutputRange();
        uint256 length = end - start;
        result = new bytes(length);
        assembly ("memory-safe") {
            mcopy(
                add(result, 0x20),
                add(add(source, 0x20), start),
                length
            )
        }
    }
}
