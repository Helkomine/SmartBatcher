// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

import "./ISmartCall.sol";
import "./Commands.sol";
import "./SmartCallPure.sol";
import "./SmartCallState.sol";
import "./ValidateAccess.sol";

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

    function smartCall(
        bytes calldata commands,
        bytes[] calldata inputs
    )
        external
        payable
        validateAccess
        returns (Output[] memory outputs)
    {
        require(commands.length == inputs.length, LengthMismatch());

        {
            uint256 count;

            // Validate command structure and count output entries.
            for (uint256 i; i < commands.length; ++i) {
                bytes1 command = commands[i];

                if (command < RETURN) ++count;
                else if (command == RETURN) require (i + 1 == commands.length, ReturnMustBeLast());
                else if (command != INPUT && command != OUTPUT) revert InvalidCommand(command);
            }

            outputs = new Output[](count);
        }

        uint256 callIndex;
        bytes memory buffer;
        bool hasPendingInput;

        for (uint256 i; i < commands.length; ++i) {
            bytes1 command = commands[i];

            if (command == INPUT) {
                buffer = _append(buffer, inputs[i]);
                hasPendingInput = true;
                continue;
            }

            if (command == OUTPUT) {
                bytes calldata directive = inputs[i];

                if (directive.length != 12) {
                    revert InvalidOutputDirective();
                }

                uint256 index = uint32(bytes4(directive[0:4]));
                uint256 start = uint32(bytes4(directive[4:8]));
                uint256 end = uint32(bytes4(directive[8:12]));

                if (index >= callIndex) {
                    revert InvalidOutputIndex();
                }

                bytes memory source = outputs[index].returnData;

                if (start > end) {
                    revert InvalidOutputRange();
                }

                // Equal bounds select the entire returndata.
                if (start == end) {
                    buffer = _append(buffer, source);
                } else {
                    if (end > source.length) {
                        revert InvalidOutputRange();
                    }

                    buffer = _append(
                        buffer,
                        _slice(source, start, end)
                    );
                }

                hasPendingInput = true;
                continue;
            }

            // CALL, STATICCALL, SELFCALL, or RETURN.
            bytes memory input;

            if (hasPendingInput) {
                input = _append(buffer, inputs[i]);
            } else {
                input = inputs[i];
                if (input.length > MAX_BUFFER_LENGTH) {
                    revert BufferTooLarge();
                }
            }

            if (command == RETURN) {
                assembly ("memory-safe") {
                    return(add(input, 0x20), mload(input))
                }
            }

            address target;
            uint256 value;
            bool allowFailure;
            bytes memory data;
            bool success;
            bytes memory returnData;

            if (command == CALL) {
                if (input.length < 53) {
                    revert InvalidInputLength();
                }

                assembly ("memory-safe") {
                    target := shr(96, mload(add(input, 0x20)))
                    value := mload(add(input, 0x34))
                }

                allowFailure = _decodeBool(uint8(input[52]));

                if (target == SELF) {
                    revert InvalidSelfTarget();
                }

                data = _slice(input, 53, input.length);

                (success, returnData) =
                    target.call{value: value}(data);

            } else if (command == STATICCALL) {
                if (input.length < 21) {
                    revert InvalidInputLength();
                }

                assembly ("memory-safe") {
                    target := shr(96, mload(add(input, 0x20)))
                }

                allowFailure = _decodeBool(uint8(input[20]));

                if (target == SELF) {
                    revert InvalidSelfTarget();
                }

                data = _slice(input, 21, input.length);

                (success, returnData) = target.staticcall(data);

            } else {
                // SELFCALL
                if (input.length < 1) {
                    revert InvalidInputLength();
                }

                allowFailure = _decodeBool(uint8(input[0]));
                data = _slice(input, 1, input.length);

                _authorizeSelfCall();

                (success, returnData) = SELF.delegatecall(data);

                _clearSelfCallAuthorization();
            }

            outputs[callIndex] = Output({
                success: success,
                returnData: returnData
            });

            ++callIndex;

            if (!success) {
                Output[] memory prefix = _prefix(outputs, callIndex);

                if (returnData.length == 0) {
                    revert CallInvalid(prefix);
                }

                if (!allowFailure) {
                    revert CallFailed(prefix);
                }
            }

            // The consumed buffer is no longer modified.
            buffer = new bytes(0);
            hasPendingInput = false;
        }

        if (hasPendingInput) {
            revert UnconsumedInput();
        }
    }

    function selectBytes(
        bool choice,
        bytes calldata inputIfTrue,
        bytes calldata inputIfFalse
    ) external payable returns (bytes memory output) {
        return choice ? inputIfTrue : inputIfFalse;
    }

    function _decodeBool(uint8 value)
        private
        pure
        returns (bool)
    {
        if (value > 1) revert InvalidAllowFailure();
        return value == 1;
    }

    function _append(
        bytes memory current,
        bytes memory part
    )
        private
        pure
        returns (bytes memory)
    {
        if (current.length > MAX_BUFFER_LENGTH) {
            revert BufferTooLarge();
        }

        if (part.length > MAX_BUFFER_LENGTH - current.length) {
            revert BufferTooLarge();
        }

        return bytes.concat(current, part);
    }

    function _slice(
        bytes memory source,
        uint256 start,
        uint256 end
    )
        private
        pure
        returns (bytes memory result)
    {
        if (start > end || end > source.length) {
            revert InvalidOutputRange();
        }

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
    )
        private
        pure
        returns (Output[] memory result)
    {
        result = new Output[](length);

        for (uint256 i; i < length; ++i) {
            result[i] = source[i];
        }
    }
}
