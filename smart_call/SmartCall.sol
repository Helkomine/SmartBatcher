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
