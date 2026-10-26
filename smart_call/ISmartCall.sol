// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;

interface ISmartCall {
    struct Output {
        bool success;
        bytes returnData;
    }
    
    function smartCall(
        bytes calldata commands,
        bytes[] calldata inputs
    ) external payable returns (Output[] memory outputs);
    
    function selectBytes(
        bool choice,
        bytes calldata inputIfTrue,
        bytes calldata inputIfFalse
    ) external payable returns (bytes memory output);
}
