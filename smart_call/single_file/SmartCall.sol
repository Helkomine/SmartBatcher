// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;

bytes1 constant CALL       = 0x00;
bytes1 constant STATICCALL = 0x01;
bytes1 constant SELFCALL   = 0x02;
bytes1 constant RETURN     = 0x03;
bytes1 constant INPUT      = 0x04;
bytes1 constant OUTPUT     = 0x05;
bytes1 constant INVALID    = 0x06;

/// @author Helkomine (@Helkomine)

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

    /// @notice Keccak256 hash function.
    /// @dev Returns a hash based on the given string of bytes.
    function hash(bytes calldata data) external payable returns (bytes32);

    function willRevert() external payable;
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

    /// @inheritdoc ISmartCallPure
    function hash(bytes calldata data) external payable returns (bytes32) {
        return keccak256(data);
    }

    error Revert();
    function willRevert() external payable {
        revert Revert();
    }
}

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

/// @notice Execution states used by the SmartCall reentrancy guard.
enum ExecutionState {
    Inactive,
    Reentrancy,
    SelfCall
}

/// @notice Raised when execution enters an unauthorized state.
error InvalidAccess();

/// @title ValidateAccess
/// @notice Transient-storage guard supporting authorized SELFCALL.
/// @dev Uses a one-time SelfCall state to authorize nested execution.
///      Only the outermost frame restores Inactive on completion.
abstract contract ValidateAccess {
    /// @dev Namespaced transient-storage slot for execution state.
    uint256 private constant ACCESS_SLOT = erc7201("access.slot");

    /// @notice Restricts execution to a top-level call or authorized SELFCALL.
    /// @dev An authorized child entry consumes SelfCall by restoring
    ///      Reentrancy before executing its function body.
    modifier validateAccess() {
        ExecutionState state = _readState();

        if (state == ExecutionState.Inactive) {
            _writeState(ExecutionState.Reentrancy);
            _;
            _writeState(ExecutionState.Inactive);
        } else if (state == ExecutionState.SelfCall) {
            _writeState(ExecutionState.Reentrancy);
            _;
        } else {
            revert InvalidAccess();
        }
    }

    /// @notice Authorizes entry into the next SELFCALL frame.
    /// @dev MUST be called immediately before the corresponding
    ///      DELEGATECALL, while the VM is actively executing.
    function _authorizeSelfCall() internal {
        if (_readState() != ExecutionState.Reentrancy) {
            revert InvalidAccess();
        }

        _writeState(ExecutionState.SelfCall);
    }

    /// @notice Restores the active execution state after SELFCALL.
    /// @dev MUST be called after DELEGATECALL returns, regardless of
    ///      success or failure, before processing the call result.
    ///      Also clears authorization restored by a reverted child.
    function _clearSelfCallAuthorization() internal {
        ExecutionState state = _readState();

        if (
            state != ExecutionState.SelfCall &&
            state != ExecutionState.Reentrancy
        ) {
            revert InvalidAccess();
        }

        _writeState(ExecutionState.Reentrancy);
    }

    /// @dev Writes the execution state to transient storage.
    /// @param state The state to store.
    function _writeState(ExecutionState state) private {
        uint256 slot = ACCESS_SLOT;
        assembly ("memory-safe") {
            tstore(slot, state)
        }
    }

    /// @dev Reads the execution state from transient storage.
    /// @return state The current execution state.
    function _readState()
        private
        view
        returns (ExecutionState state)
    {
        uint256 slot = ACCESS_SLOT;
        assembly ("memory-safe") {
            state := tload(slot)
        }
    }
}

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

// Core implementation excerpt.
// Inherit ISmartCall, SmartCallPure, SmartCallState,
// and ValidateAccess as in the existing contract.
contract SmartCall is ISmartCall, SmartCallPure, SmartCallState, ValidateAccess {
    uint256 constant MAX_BUFFER_LENGTH = type(uint32).max;

    address immutable SELF = address(this);

    error LengthMismatch();
    error InvalidCommand(bytes1 command);
    error InvalidInputLength();
    error InvalidAllowFailure();
    error InvalidSelfTarget();
    error InvalidOutputIndex();
    error InvalidOutputRange();
    error InvalidOutputDirective();
    error BufferTooLarge();
    error UnconsumedInput();
    error ReturnMustBeLast();
    error CallFailed(Output[] outputs);
    error CallInvalid(Output[] outputs);

    receive() external payable {}
    fallback() external payable {}

    function smartCall(
        bytes calldata commands,
        bytes[] calldata inputs
    ) external payable validateAccess returns (
        Output[] memory outputs
    ) {
        require(commands.length == inputs.length, LengthMismatch());

        unchecked {
            uint256 count;

            // Validate command structure and count output entries.
            for (uint256 i; i < commands.length; ++i) {
                bytes1 command = commands[i];

                if (command < INPUT) {
                    if (command < RETURN) ++count;
                    else require (i + 1 == commands.length, ReturnMustBeLast());
                } else require(command < INVALID, InvalidCommand(command));
            }

            outputs = new Output[](count);
        }

        uint256 callIndex;
        bytes memory buffer;
        bool hasPendingInput;

        unchecked {
            for (uint256 i; i < commands.length; ++i) {
                bytes1 command = commands[i];
                bytes memory input;

                if (command < INPUT) {
                    if (hasPendingInput) input = _append(buffer, inputs[i]);
                    else {
                        input = inputs[i];
                        if (input.length > MAX_BUFFER_LENGTH) revert BufferTooLarge();
                    }

                    address target;
                    uint256 value;
                    bool allowFailure;
                    bytes memory data;
                    Output memory output;

                    if (command < SELFCALL) {
                        // CALL
                        if (command < STATICCALL) {
                            if (input.length < 53) revert InvalidInputLength();

                            assembly ("memory-safe") {
                                target := shr(96, mload(add(input, 0x20)))
                                value := mload(add(input, 0x34))
                            }

                            allowFailure = _decodeBool(uint8(input[52]));

                            if (target == SELF) revert InvalidSelfTarget();

                            data = _slice(input, 53, input.length);

                            (output.success, output.returnData) = target.call{value: value}(data);
                        // STATICCALL
                        } else {
                            if (input.length < 21) revert InvalidInputLength();

                            assembly ("memory-safe") {
                                target := shr(96, mload(add(input, 0x20)))
                            }

                            allowFailure = _decodeBool(uint8(input[20]));

                            if (target == SELF) revert InvalidSelfTarget();

                            data = _slice(input, 21, input.length);

                            (output.success, output.returnData) = target.staticcall(data);
                        }
                    } else {
                        // SELFCALL
                        if (command < RETURN) {
                            if (input.length < 1) revert InvalidInputLength();

                            allowFailure = _decodeBool(uint8(input[0]));
                            data = _slice(input, 1, input.length);

                            _authorizeSelfCall();

                            (output.success, output.returnData) = SELF.delegatecall(data);

                            _clearSelfCallAuthorization();
                        // RETURN
                        } else {
                            assembly ("memory-safe") {
                                return(add(input, 0x20), mload(input))
                            }
                        }
                    }

                    outputs[callIndex++] = output;

                    if (!output.success) {
                        Output[] memory prefix = _prefix(outputs, callIndex);

                        require(output.returnData.length > 0, CallInvalid(prefix));
                        require(allowFailure, CallFailed(prefix));
                    }

                    // The consumed buffer is no longer modified.
                    buffer = new bytes(0);
                    hasPendingInput = false;
                } else {
                    // INPUT
                    if (command < OUTPUT) buffer = _append(buffer, inputs[i]);
                    // OUTPUT
                    else {
                        bytes calldata directive = inputs[i];

                        if (directive.length != 12) revert InvalidOutputDirective();

                        uint256 index = uint32(bytes4(directive[0 : 4]));
                        uint256 start = uint32(bytes4(directive[4 : 8]));
                        uint256 end = uint32(bytes4(directive[8 : 12]));

                        require(index < callIndex, InvalidOutputIndex());

                        bytes memory source = outputs[index].returnData;

                        if (start > end) revert InvalidOutputRange();

                        // Equal bounds select the entire returndata.
                        if (start == end) buffer = _append(buffer, source);
                        else {
                            if (end > source.length) revert InvalidOutputRange();

                            buffer = _append(
                                buffer,
                                _slice(source, start, end)
                            );
                        }
                    }

                    hasPendingInput = true;
                }
            }
        }

        if (hasPendingInput) revert UnconsumedInput();
    }

    function selectBytes(
        bool choice,
        bytes calldata inputIfTrue,
        bytes calldata inputIfFalse
    ) external payable returns (
        bytes memory output
    ) {
        return choice ? inputIfTrue : inputIfFalse;
    }

    function _decodeBool(uint8 value) private pure returns (bool) {
        if (value > 1) revert InvalidAllowFailure();
        return value == 1;
    }

    function _append(
        bytes memory current,
        bytes memory part
    ) private pure returns (bytes memory) {
        if (current.length > MAX_BUFFER_LENGTH) revert BufferTooLarge();
        if (part.length > MAX_BUFFER_LENGTH - current.length) revert BufferTooLarge();

        return bytes.concat(current, part);
    }

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

    function _prefix(
        Output[] memory source,
        uint256 length
    ) private pure returns (
        Output[] memory result
    ) {
        result = new Output[](length);

        for (uint256 i; i < length; ++i) result[i] = source[i];
    }
}
