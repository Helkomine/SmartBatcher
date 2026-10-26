// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;

enum ExecutionState {
    Inactive,
    Reentrancy,
    SelfCall
}

error InvalidAccess();

abstract contract ValidateAccess {
    uint256 constant ACCESS_SLOT = erc7201("access.slot");

    modifier validateAccess {
        ExecutionState state = _readState();
        if (state == ExecutionState.Inactive) {
            _writeState(ExecutionState.Reentrancy);
            _;
            _writeState(ExecutionState.Inactive);
        } else if (state == ExecutionState.SelfCall) {
            _writeState(ExecutionState.Reentrancy);
            _;
        } else revert InvalidAccess();
    }

    function _writeState(ExecutionState state) internal {
        uint256 slot = ACCESS_SLOT;
        assembly ("memory-safe") {
            tstore(slot, state)
        }
    }

    function _readState() internal view returns (ExecutionState state) {
        uint256 slot = ACCESS_SLOT;
        assembly ("memory-safe") {
            state := tload(slot)
        }
    }
}
