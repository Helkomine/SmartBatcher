// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

interface IMulticall4 {
    enum Route {
        RAW,
        OUTPUT
    }

    struct Target {
        Route route;
        bytes32 input;
    }

    struct Value {
        Route route;
        bytes32 input;
    }

    struct Data {
        Route route;
        bytes input;
    }

    struct Batch {
        Target target;
        Value value;
        Data[] data;
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

    function multicall(Batch[] calldata batches) external payable returns (Result[] memory results) {
        results = new Result[](batches.length);
        for (uint256 i = 0 ; i < batches.length ; ) {
            Batch calldata batch = batches[i];
            address target;
            if (batch.target.route == IMulticall4.Route.RAW) {
                target = address(bytes20(batch.target.input));
            } else {
                bytes32 _input = batch.target.input;
                uint64 index = uint256(_input) >> 192;
                uint64 start = (uint256(_input) << 64) >> 192;
                require(index < i, InvalidIndex(index));
                result = results[index];
                target = address(bytes20(result.returnData[start : start + 20]));
            }
            uint256 value;
            if (batch.value.route == IMulticall4.Route.RAW) {
                value = uint256(batch.target.input);
            } else {
                bytes32 _input = batch.target.input;
                uint64 index = uint256(_input) >> 192;
                uint64 start = (uint256(_input) << 64) >> 192;
                require(index < i, InvalidIndex(index));
                result = results[index];
                target = bytes32(result.returnData[start : start + 32]);
            }
            bytes memory data;
            for (uint256 j = 0 ; j < batch.data.length ; ) {
                Data calldata _data = batch.data[j];
                if (_data.route == IMulticall4.Route.RAW) {
                    data = bytes.concat(data, _data.data);
                } else {
                    uint64 index = uint256(_input) >> 192;
                    uint64 start = (uint256(_input) << 64) >> 192;
                    uint64 end = (uint256(_input) << 128) >> 192;
                    uint64 sentinel = uint256(_input) & SENTINEL;
                    require(index < i, InvalidIndex(index));
                    result = results[index];
                    if (sentinel == SENTINEL) {
                        data = bytes.concat(data, result.returnData[start : result.returnData.length - end]);
                    } else {
                        data = bytes.concat(data, result.returnData[start : end];  
                    }
                }
                unchecked { ++j; }
            }
            Result memory result = results[i];
            (result.success, result.returnData) = target.call{value : value}(data);
            require(result.success, CallFailed(result.returnData));
            unchecked { ++i; }
        }
    }
}
