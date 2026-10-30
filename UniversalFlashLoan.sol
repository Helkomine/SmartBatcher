// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;

contract SmartFlashLoan {
    /**
     * @dev Maximum number of bytes that a cache entry can contain.
     *
     * This limit protects the transient-storage cache implementation and is
     * not part of the Solver protocol semantics.
     */
    uint64 constant MAX_TOTAL_LENGTH = type(uint64).max;

    /**
     * @dev Mask used to extract the lower 128-bit `length` field from
     *      `sliceInfo`.
     */
    uint256 constant SLICE_INFO_MASKING = type(uint128).max;

    uint256 constant DEPTH_SLOT = erc7201("depth.slot");

    uint256 constant BYTECODE_SLOT = erc7201("bytecode.slot");

    uint256 constant CALLDATA_SLOT = erc7201("calldata.slot");

    address immutable EXECUTOR;

    /**
     * @dev Reverts when transient-storage slot arithmetic overflows.
     *
     * This error protects the cache implementation and is not part of the
     * Solver protocol semantics.
     */
    error Overflow();

    /**
     * @dev Reverts when a cached `bytes` value exceeds
     *      `MAX_TOTAL_LENGTH`.
     *
     * @param totalLength The length that exceeded the implementation limit.
     */
    error TotalLengthTooLarge(uint256 totalLength);

    constructor(address executor) {
        EXECUTOR = executor;
    }

    fallback() external payable {
        uint256 depth = _tload(bytes32(DEPTH_SLOT));
        unchecked { _tstore(bytes32(DEPTH_SLOT), ++depth); }
        if (depth == 1) {
            _setCacheCallData(bytes32(BYTECODE_SLOT), msg.data);
            (bool success, bytes memory retData) = EXECUTOR.delegatecall(msg.data);
            if (success) {
                unchecked { _tstore(bytes32(DEPTH_SLOT), --depth); }
                _setCacheData(bytes32(CALLDATA_SLOT), new bytes(0));
                _setCacheData(bytes32(BYTECODE_SLOT), new bytes(0));
                assembly ("memory-safe") {
                    return(add(retData, 0x20), mload(retData))
                }
            } else {
                assembly ("memory-safe") {
                    revert(add(retData, 0x20), mload(retData))
                }
            }
        } else {
            _setCacheCallData(bytes32(CALLDATA_SLOT), msg.data);
            (bool success, bytes memory retData) = EXECUTOR.delegatecall(_getCacheData(bytes32(BYTECODE_SLOT)));
            if (success) {
                unchecked { _tstore(bytes32(DEPTH_SLOT), --depth); }
                assembly ("memory-safe") {
                    return(add(retData, 0x20), mload(retData))
                }
            } else {
                assembly ("memory-safe") {
                    revert(add(retData, 0x20), mload(retData))
                }
            }
        }
    }

    /**
     * @dev Copies a `bytes` value from calldata into transient storage.
     *
     * The value is stored as a length word followed by its data words. If the
     * length is not a multiple of 32 bytes, the unused bytes in the final word
     * are zeroed to produce a canonical representation.
     *
     * If the new value is shorter than the previously cached value at the same
     * namespace, trailing transient storage slots are cleared to prevent stale
     * data from remaining in the cache.
     *
     * Reverts with `TotalLengthTooLarge` if the value or previous cached value
     * exceeds `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage
     * slot arithmetic overflows.
     *
     * @param namespace The transient storage namespace used to cache the value.
     * @param data The calldata bytes to cache.
     */
    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := data.length
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot
            {
                let _cacheLength := add(cacheLength, 31)
                if gt(cacheLength, _cacheLength) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                totalCacheSlot := shr(5, _cacheLength)
            }
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := data.offset
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), calldataload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := calldataload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot) {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, cacheLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

    /**
     * @dev Copies a `bytes` value from memory into transient storage.
     *
     * The value is stored as a length word followed by its data words. If the
     * length is not a multiple of 32 bytes, the unused bytes in the final word
     * are zeroed to produce a canonical representation.
     *
     * If the new value is shorter than the previously cached value at the same
     * namespace, trailing transient storage slots are cleared to prevent stale
     * data from remaining in the cache.
     *
     * Reverts with `TotalLengthTooLarge` if the value or previous cached value
     * exceeds `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage
     * slot arithmetic overflows.
     *
     * @param namespace The transient storage namespace used to cache the value.
     * @param data The memory bytes to cache.
     */
    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := mload(data)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot := shr(5, add(cacheLength, 31))
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := add(data, 32)
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), mload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := mload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot)  {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, maxTotalLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

    /**
     * @dev Loads a cached `bytes` value from transient storage into memory.
     *
     * The value is expected to be stored as a length word followed by its data
     * words. If the length is not a multiple of 32 bytes, only the bytes within
     * the logical length are copied into memory; unused bytes in the final word
     * are ignored.
     *
     * Reverts with `TotalLengthTooLarge` if the cached length exceeds
     * `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage slot
     * arithmetic overflows.
     *
     * @param namespace The transient storage namespace containing the cached value.
     * @return data The cached bytes value reconstructed in memory.
     */
    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            data := mload(64)
            let length := tload(namespace)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            mstore(data, length)
            let offset := add(data, 32)
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                let lastSlot := add(namespace, floorTotalSlot)
                {
                    let _namespace := add(namespace, 1)
                    if gt(namespace, _namespace) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                    namespace := _namespace
                    if gt(namespace, lastSlot) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                }
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    mstore(add(offset, shl(5, i)), tload(add(namespace, i)))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := tload(lastSlot)
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    mstore(add(offset, roundingLength), mask)
                }
                offset := add(offset, shl(5, totalSlot))
            }
            mstore(64, offset)
        }
    }

    /**
     * @dev Stores a value in transient storage at `key`.
     *
     * This helper provides a high-level Solidity-callable wrapper around the
     * `TSTORE` instruction.
     *
     * @param key The transient storage key.
     * @param value The value to store.
     */
    function _tstore(bytes32 key, uint256 value) internal {
        assembly ("memory-safe") {
            tstore(key, value)
        }
    }

    /**
     * @dev Loads a value from transient storage at `key`.
     *
     * This helper provides a high-level Solidity-callable wrapper around the
     * `TLOAD` instruction.
     *
     * @param key The transient storage key.
     * @return value The value stored at `key`.
     */
    function _tload(bytes32 key) internal view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(key)
        }
    }
}
