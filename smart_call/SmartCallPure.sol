
 // SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;

/// @title ISmartCallPure
/// @notice Optional arithmetic and comparison helpers for SmartCall.
/// @dev All functions are payable to support SELFCALL via DELEGATECALL
///      when the inherited msg.value is nonzero.
///      These functions must not modify state or perform external calls.
interface ISmartCallPure {
    /// @notice Adds two unsigned integers with modulo 2^256 arithmetic.
    function add(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Subtracts two unsigned integers with modulo 2^256 arithmetic.
    function sub(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Multiplies two unsigned integers with modulo 2^256 arithmetic.
    function mul(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Performs EVM unsigned division, returning zero if b is zero.
    function div(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Adds two integers, reverting on overflow.
    function safeAdd(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Subtracts two integers, reverting on underflow.
    function safeSub(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Multiplies two integers, reverting on overflow.
    function safeMul(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Divides two integers, reverting if b is zero.
    function safeDiv(uint256 a, uint256 b) external payable returns (uint256);

    /// @notice Returns whether a is less than b.
    function lt(uint256 a, uint256 b) external payable returns (bool);

    /// @notice Returns whether a is greater than b.
    function gt(uint256 a, uint256 b) external payable returns (bool);

    /// @notice Returns whether a equals b.
    function eq(uint256 a, uint256 b) external payable returns (bool);

    /// @notice Checks whether num is within the inclusive bounds.
    /// @dev Returns false when lowest is greater than highest.
    function range(
        uint256 lowest,
        uint256 highest,
        uint256 num
    ) external payable returns (bool);
}

/// @title SmartCallPure
/// @notice Reference implementation of SmartCall arithmetic helpers.
/// @dev Functions are computationally pure in behavior, despite being
///      declared payable for compatibility with SELFCALL.
abstract contract SmartCallPure is ISmartCallPure {
    /// @notice Raised when a checked arithmetic operation overflows
    ///         or underflows.
    error ArithmeticOverflow();

    /// @notice Raised when checked division has a zero divisor.
    error DivisionByZero();

    /// @inheritdoc ISmartCallPure
    function add(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        unchecked {
            return a + b;
        }
    }

    /// @inheritdoc ISmartCallPure
    function sub(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        unchecked {
            return a - b;
        }
    }

    /// @inheritdoc ISmartCallPure
    function mul(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        unchecked {
            return a * b;
        }
    }

    /// @inheritdoc ISmartCallPure
    function div(uint256 a, uint256 b)
        external payable override returns (uint256 result)
    {
        assembly {
            result := div(a, b)
        }
    }

    /// @inheritdoc ISmartCallPure
    function safeAdd(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        unchecked {
            uint256 c = a + b;
            if (c < a) revert ArithmeticOverflow();
            return c;
        }
    }

    /// @inheritdoc ISmartCallPure
    function safeSub(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        if (b > a) revert ArithmeticOverflow();

        unchecked {
            return a - b;
        }
    }

    /// @inheritdoc ISmartCallPure
    function safeMul(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        unchecked {
            if (a == 0) return 0;

            uint256 c = a * b;
            if (c / a != b) revert ArithmeticOverflow();

            return c;
        }
    }

    /// @inheritdoc ISmartCallPure
    function safeDiv(uint256 a, uint256 b)
        external payable override returns (uint256)
    {
        if (b == 0) revert DivisionByZero();
        return a / b;
    }

    /// @inheritdoc ISmartCallPure
    function lt(uint256 a, uint256 b)
        external payable override returns (bool)
    {
        return a < b;
    }

    /// @inheritdoc ISmartCallPure
    function gt(uint256 a, uint256 b)
        external payable override returns (bool)
    {
        return a > b;
    }

    /// @inheritdoc ISmartCallPure
    function eq(uint256 a, uint256 b)
        external payable override returns (bool)
    {
        return a == b;
    }

    /// @inheritdoc ISmartCallPure
    function range(
        uint256 lowest,
        uint256 highest,
        uint256 num
    ) external payable override returns (bool)
    {
        return lowest <= num && num <= highest;
    }
}
