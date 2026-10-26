
 // SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;

/// @title ISmartCallState
/// @notice Optional EVM execution-context queries for SmartCall.
/// @dev Functions are payable to support SELFCALL via DELEGATECALL.
///      These functions must not modify state or perform external calls.
interface ISmartCallState {
    /// @notice Returns the caller in the current execution context.
    /// @dev Corresponds to the EVM CALLER opcode.
    function msgSender() external payable returns (address);

    /// @notice Returns the call value in the current execution context.
    /// @dev Corresponds to the EVM CALLVALUE opcode.
    function msgValue() external payable returns (uint256);

    /// @notice Returns the current execution-context address.
    /// @dev Corresponds to the EVM ADDRESS opcode.
    function addressThis() external payable returns (address);

    /// @notice Returns the ETH balance of an account.
    /// @dev Corresponds to the EVM BALANCE opcode.
    /// @param viewer The account whose ETH balance is queried.
    function balanceETH(address viewer)
        external payable returns (uint256);
}

/// @title SmartCallState
/// @notice Reference implementation of SmartCall context-query helpers.
/// @dev SELFCALL preserves msg.sender, msg.value, and address(this)
///      through DELEGATECALL. These values may differ from the original
///      transaction sender and the deployed implementation address.
abstract contract SmartCallState is ISmartCallState {
    /// @inheritdoc ISmartCallState
    function msgSender()
        external payable override returns (address)
    {
        return msg.sender;
    }

    /// @inheritdoc ISmartCallState
    function msgValue()
        external payable override returns (uint256)
    {
        return msg.value;
    }

    /// @inheritdoc ISmartCallState
    function addressThis()
        external payable override returns (address)
    {
        return address(this);
    }

    /// @inheritdoc ISmartCallState
    function balanceETH(address viewer)
        external payable override returns (uint256)
    {
        return viewer.balance;
    }
}
