// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../types/DataTypes.sol";
import "./InputParser.sol";

/**
 * @title RuleChecker
 * @dev Library for checking protection rules against transactions
 */
library RuleChecker {
    using InputParser for bytes;

    /**
     * @dev Check if transaction triggers any protection rules
     * @param rules Array of protection rules to check
     * @param inputData Transaction input data
     * @param caller Transaction caller address
     * @return result Detection result
     */
    function checkRules(DataTypes.ProtectionRule[] storage rules, bytes calldata inputData, address caller)
        internal
        view
        returns (DataTypes.DetectionResult memory result)
    {
        result.isAttack = false;
        result.confidence = 0;
        result.triggeredRules = new string[](0);

        string[] memory triggeredRuleIds = new string[](rules.length);
        uint256 triggeredCount = 0;
        uint256 totalConfidence = 0;

        for (uint256 i = 0; i < rules.length; i++) {
            if (!rules[i].isActive) {
                continue;
            }

            bool ruleTriggered = false;
            uint256 ruleConfidence = 0;

            // Check input rules
            if (rules[i].inputRules.length > 0) {
                (bool inputTriggered, uint256 inputConfidence) = checkInputRules(rules[i].inputRules, inputData);
                if (inputTriggered) {
                    ruleTriggered = true;
                    ruleConfidence = inputConfidence;
                }
            }

            // Check storage rules
            if (rules[i].storageRules.length > 0) {
                (bool storageTriggered, uint256 storageConfidence) = checkStorageRules(rules[i].storageRules);
                if (storageTriggered) {
                    ruleTriggered = true;
                    ruleConfidence = storageConfidence;
                }
            }

            if (ruleTriggered) {
                triggeredRuleIds[triggeredCount] = rules[i].ruleId;
                triggeredCount++;
                totalConfidence += ruleConfidence;
            }
        }

        if (triggeredCount > 0) {
            result.isAttack = true;
            result.confidence = totalConfidence / triggeredCount;
            result.triggeredRules = new string[](triggeredCount);

            for (uint256 i = 0; i < triggeredCount; i++) {
                result.triggeredRules[i] = triggeredRuleIds[i];
            }

            result.reason = "Multiple protection rules triggered";
        }

        return result;
    }

    /**
     * @dev Check input protection rules
     * @param inputRules Array of input rules
     * @param inputData Transaction input data
     * @return triggered Whether any input rule was triggered
     * @return confidence Confidence score
     */
    function checkInputRules(DataTypes.InputRule[] storage inputRules, bytes calldata inputData)
        internal
        view
        returns (bool triggered, uint256 confidence)
    {
        bytes4 functionSelector = InputParser.extractFunctionSelector(inputData);

        for (uint256 i = 0; i < inputRules.length; i++) {
            if (!inputRules[i].isActive) {
                continue;
            }

            // Check function selector match
            if (inputRules[i].functionSelector != functionSelector) {
                continue;
            }

            // Check parameter rules
            bool parameterMatch = true;
            for (uint256 j = 0; j < inputRules[i].parameters.length; j++) {
                if (!checkParameterRule(inputRules[i].parameters[j], inputData)) {
                    parameterMatch = false;
                    break;
                }
            }

            if (parameterMatch) {
                triggered = true;
                confidence = 8000; // High confidence for input rule match
                break;
            }
        }

        return (triggered, confidence);
    }

    /**
     * @dev Check storage protection rules
     * @param storageRules Array of storage rules
     * @return triggered Whether any storage rule was triggered
     * @return confidence Confidence score
     */
    function checkStorageRules(DataTypes.StorageRule[] storage storageRules)
        internal
        view
        returns (bool triggered, uint256 confidence)
    {
        for (uint256 i = 0; i < storageRules.length; i++) {
            if (!storageRules[i].isActive) {
                continue;
            }

            // Read storage value from the target contract
            bytes32 currentValue = _readStorageSlot(storageRules[i].contractAddress, storageRules[i].storageSlot);

            // Check if current value matches the attack pattern
            if (checkStorageValue(storageRules[i], currentValue)) {
                triggered = true;
                confidence = 7000; // High confidence for storage rule match
                break;
            }
        }

        return (triggered, confidence);
    }

    /**
     * @dev Check individual parameter rule
     * @param paramRule Parameter rule to check
     * @param inputData Transaction input data
     * @return matches Whether parameter matches the rule
     */
    function checkParameterRule(DataTypes.ParameterRule storage paramRule, bytes calldata inputData)
        internal
        view
        returns (bool matches)
    {
        if (!paramRule.isActive) {
            return false;
        }

        bytes32 paramValue = InputParser.extractParameter(inputData, paramRule.index);

        if (paramRule.checkType == DataTypes.CheckType.EXACT) {
            return paramValue == paramRule.modifiedValue;
        } else if (paramRule.checkType == DataTypes.CheckType.RANGE) {
            uint256 value = uint256(paramValue);
            return value >= paramRule.minValue && value <= paramRule.maxValue;
        }

        // For other check types, implement specific logic
        return false;
    }

    /**
     * @dev Check storage value against rule
     * @param storageRule Storage rule to check
     * @param currentValue Current storage value
     * @return matches Whether storage value matches the rule
     */
    function checkStorageValue(DataTypes.StorageRule storage storageRule, bytes32 currentValue)
        internal
        view
        returns (bool matches)
    {
        if (storageRule.checkType == DataTypes.CheckType.EXACT) {
            return currentValue == storageRule.modifiedValue;
        } else if (storageRule.checkType == DataTypes.CheckType.RANGE) {
            uint256 value = uint256(currentValue);
            return value >= storageRule.minValue && value <= storageRule.maxValue;
        } else if (storageRule.checkType == DataTypes.CheckType.DELTA) {
            uint256 originalValue = uint256(storageRule.originalValue);
            uint256 currentValueUint = uint256(currentValue);
            uint256 delta =
                currentValueUint > originalValue ? currentValueUint - originalValue : originalValue - currentValueUint;
            return delta <= storageRule.maxValue;
        }

        return false;
    }

    /**
     * @dev Read storage slot from external contract
     * @param contractAddress Contract address
     * @param slot Storage slot
     * @return value Storage value
     */
    function _readStorageSlot(address contractAddress, bytes32 slot) private view returns (bytes32 value) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, slot)

            let success := staticcall(gas(), contractAddress, ptr, 0x20, ptr, 0x20)

            if success { value := mload(ptr) }
        }
    }

    /**
     * @dev Calculate rule matching confidence
     * @param rule Protection rule
     * @param inputData Transaction input data
     * @return confidence Confidence score (0-10000 basis points)
     */
    function calculateRuleConfidence(DataTypes.ProtectionRule storage rule, bytes calldata inputData)
        internal
        view
        returns (uint256 confidence)
    {
        uint256 inputConfidence = 0;
        uint256 storageConfidence = 0;

        // Calculate input confidence
        if (rule.inputRules.length > 0) {
            (bool inputTriggered, uint256 inputConf) = checkInputRules(rule.inputRules, inputData);
            if (inputTriggered) {
                inputConfidence = inputConf;
            }
        }

        // Calculate storage confidence
        if (rule.storageRules.length > 0) {
            (bool storageTriggered, uint256 storageConf) = checkStorageRules(rule.storageRules);
            if (storageTriggered) {
                storageConfidence = storageConf;
            }
        }

        // Combine confidences
        if (inputConfidence > 0 && storageConfidence > 0) {
            confidence = (inputConfidence + storageConfidence) / 2;
        } else if (inputConfidence > 0) {
            confidence = inputConfidence;
        } else if (storageConfidence > 0) {
            confidence = storageConfidence;
        }

        // Apply similarity multiplier
        confidence = (confidence * rule.similarity) / 10000;

        return confidence;
    }

    /**
     * @dev Validate protection rule
     * @param rule Protection rule to validate
     * @return isValid Whether rule is valid
     */
    function validateRule(DataTypes.ProtectionRule memory rule) internal pure returns (bool isValid) {
        // Check basic fields
        if (bytes(rule.ruleId).length == 0) {
            return false;
        }

        if (rule.protectedContract == address(0)) {
            return false;
        }

        if (rule.similarity == 0 || rule.similarity > 10000) {
            return false;
        }

        // Must have at least one rule type
        if (rule.inputRules.length == 0 && rule.storageRules.length == 0) {
            return false;
        }

        // Validate input rules
        for (uint256 i = 0; i < rule.inputRules.length; i++) {
            if (rule.inputRules[i].functionSelector == bytes4(0)) {
                return false;
            }
        }

        // Validate storage rules
        for (uint256 i = 0; i < rule.storageRules.length; i++) {
            if (rule.storageRules[i].contractAddress == address(0)) {
                return false;
            }
        }

        return true;
    }
}
