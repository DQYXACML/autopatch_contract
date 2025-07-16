// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../types/DataTypes.sol";

/**
 * @title InputParser
 * @dev Library for parsing transaction input data
 */
library InputParser {
    /**
     * @dev Extract function selector from input data
     * @param inputData Transaction input data
     * @return selector Function selector
     */
    function extractFunctionSelector(bytes calldata inputData) internal pure returns (bytes4 selector) {
        if (inputData.length < 4) {
            return bytes4(0);
        }

        return bytes4(inputData[0:4]);
    }

    /**
     * @dev Extract parameter at specific index from input data
     * @param inputData Transaction input data
     * @param paramIndex Parameter index (0-based)
     * @return value Parameter value as bytes32
     */
    function extractParameter(bytes calldata inputData, uint256 paramIndex) internal pure returns (bytes32 value) {
        if (inputData.length < 4 + (paramIndex + 1) * 32) {
            return bytes32(0);
        }

        uint256 offset = 4 + paramIndex * 32;

        // Convert calldata slice to bytes32
        bytes calldata paramSlice = inputData[offset:offset + 32];
        assembly {
            value := calldataload(paramSlice.offset)
        }
    }

    /**
     * @dev Extract dynamic parameter (like string or bytes) from input data
     * @param inputData Transaction input data
     * @param paramIndex Parameter index (0-based)
     * @return data Dynamic parameter data
     */
    function extractDynamicParameter(bytes calldata inputData, uint256 paramIndex)
        internal
        pure
        returns (bytes memory data)
    {
        if (inputData.length < 4 + (paramIndex + 1) * 32) {
            return new bytes(0);
        }

        // Get the offset pointer
        uint256 offsetPointer = 4 + paramIndex * 32;
        if (offsetPointer + 32 > inputData.length) {
            return new bytes(0);
        }

        // Read the offset value
        bytes32 offsetValue = extractParameter(inputData, paramIndex);
        uint256 dataOffset = uint256(offsetValue);

        // Check if offset is valid
        if (4 + dataOffset + 32 > inputData.length) {
            return new bytes(0);
        }

        // Read the length
        bytes calldata lengthSlice = inputData[4 + dataOffset:4 + dataOffset + 32];
        uint256 dataLength;
        assembly {
            dataLength := calldataload(lengthSlice.offset)
        }

        // Check if we have enough data
        if (4 + dataOffset + 32 + dataLength > inputData.length) {
            return new bytes(0);
        }

        // Extract the actual data
        return inputData[4 + dataOffset + 32:4 + dataOffset + 32 + dataLength];
    }

    /**
     * @dev Parse address parameter
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return addr Address value
     */
    function parseAddress(bytes calldata inputData, uint256 paramIndex) internal pure returns (address addr) {
        bytes32 value = extractParameter(inputData, paramIndex);
        return address(uint160(uint256(value)));
    }

    /**
     * @dev Parse uint256 parameter
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return value Uint256 value
     */
    function parseUint256(bytes calldata inputData, uint256 paramIndex) internal pure returns (uint256 value) {
        bytes32 raw = extractParameter(inputData, paramIndex);
        return uint256(raw);
    }

    /**
     * @dev Parse boolean parameter
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return value Boolean value
     */
    function parseBool(bytes calldata inputData, uint256 paramIndex) internal pure returns (bool value) {
        bytes32 raw = extractParameter(inputData, paramIndex);
        return uint256(raw) != 0;
    }

    /**
     * @dev Parse string parameter
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return value String value
     */
    function parseString(bytes calldata inputData, uint256 paramIndex) internal pure returns (string memory value) {
        bytes memory data = extractDynamicParameter(inputData, paramIndex);
        return string(data);
    }

    /**
     * @dev Parse bytes parameter
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return value Bytes value
     */
    function parseBytes(bytes calldata inputData, uint256 paramIndex) internal pure returns (bytes memory value) {
        return extractDynamicParameter(inputData, paramIndex);
    }

    /**
     * @dev Calculate parameter hash for comparison
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return hash Parameter hash
     */
    function calculateParameterHash(bytes calldata inputData, uint256 paramIndex)
        internal
        pure
        returns (bytes32 hash)
    {
        bytes32 value = extractParameter(inputData, paramIndex);
        return keccak256(abi.encode(value));
    }

    /**
     * @dev Calculate input data hash
     * @param inputData Transaction input data
     * @return hash Input data hash
     */
    function calculateInputHash(bytes calldata inputData) internal pure returns (bytes32 hash) {
        return keccak256(inputData);
    }

    /**
     * @dev Check if input matches pattern
     * @param inputData Transaction input data
     * @param pattern Pattern to match
     * @return matches Whether input matches pattern
     */
    function matchesPattern(bytes calldata inputData, bytes calldata pattern) internal pure returns (bool matches) {
        if (inputData.length != pattern.length) {
            return false;
        }

        return keccak256(inputData) == keccak256(pattern);
    }

    /**
     * @dev Validate input data format
     * @param inputData Transaction input data
     * @return isValid Whether input data is valid
     */
    function validateInputData(bytes calldata inputData) internal pure returns (bool isValid) {
        // Must have at least function selector
        if (inputData.length < 4) {
            return false;
        }

        // For most cases, parameter data should be properly aligned (32-byte chunks after selector)
        // But we allow dynamic data which might not follow this rule
        return true;
    }

    /**
     * @dev Compare two input data for similarity
     * @param inputData1 First input data
     * @param inputData2 Second input data
     * @return similarity Similarity score (0-10000 basis points)
     */
    function calculateSimilarity(bytes calldata inputData1, bytes calldata inputData2)
        internal
        pure
        returns (uint256 similarity)
    {
        if (inputData1.length == 0 && inputData2.length == 0) {
            return 10000; // 100% similar
        }

        if (inputData1.length == 0 || inputData2.length == 0) {
            return 0; // 0% similar
        }

        // Check function selector similarity
        bytes4 selector1 = extractFunctionSelector(inputData1);
        bytes4 selector2 = extractFunctionSelector(inputData2);

        if (selector1 != selector2) {
            return 0; // Different functions are not similar
        }

        // Calculate parameter similarity
        uint256 minLength = inputData1.length < inputData2.length ? inputData1.length : inputData2.length;
        uint256 maxLength = inputData1.length > inputData2.length ? inputData1.length : inputData2.length;

        if (maxLength <= 4) {
            return 10000; // Only function selector, 100% similar
        }

        uint256 matchingBytes = 4; // Function selector already matches
        for (uint256 i = 4; i < minLength; i++) {
            if (inputData1[i] == inputData2[i]) {
                matchingBytes++;
            }
        }

        // Calculate similarity as percentage
        similarity = (matchingBytes * 10000) / maxLength;

        return similarity;
    }

    /**
     * @dev Extract parameter value as specific type
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @param paramType Parameter type ("uint256", "address", "bool", etc.)
     * @return value Parameter value as bytes
     */
    function extractParameterAsType(bytes calldata inputData, uint256 paramIndex, string memory paramType)
        internal
        pure
        returns (bytes memory value)
    {
        bytes32 hashType = keccak256(bytes(paramType));

        if (hashType == keccak256("uint256") || hashType == keccak256("int256") || hashType == keccak256("bytes32")) {
            bytes32 param = extractParameter(inputData, paramIndex);
            return abi.encode(param);
        } else if (hashType == keccak256("address")) {
            address param = parseAddress(inputData, paramIndex);
            return abi.encode(param);
        } else if (hashType == keccak256("bool")) {
            bool param = parseBool(inputData, paramIndex);
            return abi.encode(param);
        } else if (hashType == keccak256("string")) {
            string memory param = parseString(inputData, paramIndex);
            return bytes(param);
        } else if (hashType == keccak256("bytes")) {
            return parseBytes(inputData, paramIndex);
        } else {
            // Default: treat as bytes32
            bytes32 param = extractParameter(inputData, paramIndex);
            return abi.encode(param);
        }
    }

    /**
     * @dev Get number of parameters in input data (estimate)
     * @param inputData Transaction input data
     * @return count Estimated parameter count
     */
    function getParameterCount(bytes calldata inputData) internal pure returns (uint256 count) {
        if (inputData.length < 4) {
            return 0;
        }

        // Simple estimation: (length - 4) / 32
        // This works for static parameters only
        uint256 dataLength = inputData.length - 4;
        return dataLength / 32;
    }

    /**
     * @dev Check if parameter at index exists
     * @param inputData Transaction input data
     * @param paramIndex Parameter index
     * @return exists Whether parameter exists
     */
    function parameterExists(bytes calldata inputData, uint256 paramIndex) internal pure returns (bool exists) {
        return inputData.length >= 4 + (paramIndex + 1) * 32;
    }
}
