// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../types/DataTypes.sol";

/**
 * @title IDefenseContract
 * @dev Interface for the defense contract
 */
interface IDefenseContract {
    /**
     * @dev Main detection function to be called before protected contract execution
     * @param protectedContract Address of the protected contract
     * @param inputData Transaction input data
     * @param caller Address of the transaction caller
     * @return result Detection result
     */
    function detect(address protectedContract, bytes calldata inputData, address caller)
        external
        returns (DataTypes.DetectionResult memory result);

    /**
     * @dev Add a new protection rule
     * @param rule The protection rule to add
     */
    function addRule(DataTypes.ProtectionRule calldata rule) external;

    /**
     * @dev Add multiple protection rules in batch
     * @param rules Array of protection rules to add
     */
    function addRules(DataTypes.ProtectionRule[] calldata rules) external;

    /**
     * @dev Update an existing protection rule
     * @param ruleId Rule identifier
     * @param rule Updated rule data
     */
    function updateRule(string calldata ruleId, DataTypes.ProtectionRule calldata rule) external;

    /**
     * @dev Remove a protection rule
     * @param protectedContract Address of the protected contract
     * @param ruleId Rule identifier
     */
    function removeRule(address protectedContract, string calldata ruleId) external;

    /**
     * @dev Enable or disable a protection rule
     * @param protectedContract Address of the protected contract
     * @param ruleId Rule identifier
     * @param isActive Whether to activate the rule
     */
    function setRuleActive(address protectedContract, string calldata ruleId, bool isActive) external;

    /**
     * @dev Get all rules for a protected contract
     * @param protectedContract Address of the protected contract
     * @return rules Array of protection rules
     */
    function getRules(address protectedContract) external view returns (DataTypes.ProtectionRule[] memory rules);

    /**
     * @dev Get a specific rule by ID
     * @param protectedContract Address of the protected contract
     * @param ruleId Rule identifier
     * @return rule The protection rule
     */
    function getRule(address protectedContract, string calldata ruleId)
        external
        view
        returns (DataTypes.ProtectionRule memory rule);

    /**
     * @dev Get rule statistics
     * @param protectedContract Address of the protected contract
     * @param ruleId Rule identifier
     * @return stats Rule statistics
     */
    function getRuleStats(address protectedContract, string calldata ruleId)
        external
        view
        returns (DataTypes.RuleStats memory stats);

    /**
     * @dev Store mutation data from off-chain analysis
     * @param protectedContract Address of the protected contract
     * @param originalTxHash Original transaction hash
     * @param mutations Array of mutation data
     */
    function storeMutationData(
        address protectedContract,
        bytes32 originalTxHash,
        DataTypes.MutationData[] calldata mutations
    ) external;

    /**
     * @dev Get stored mutation data
     * @param protectedContract Address of the protected contract
     * @param originalTxHash Original transaction hash
     * @return mutations Array of mutation data
     */
    function getMutationData(address protectedContract, bytes32 originalTxHash)
        external
        view
        returns (DataTypes.MutationData[] memory mutations);

    /**
     * @dev Enable or disable protection for a contract
     * @param protectedContract Address of the protected contract
     * @param enabled Whether to enable protection
     */
    function setProtectionEnabled(address protectedContract, bool enabled) external;

    /**
     * @dev Get protection configuration for a contract
     * @param protectedContract Address of the protected contract
     * @return config Protection configuration
     */
    function getProtectionConfig(address protectedContract)
        external
        view
        returns (DataTypes.ProtectionConfig memory config);

    /**
     * @dev Report a false positive
     * @param protectedContract Address of the protected contract
     * @param ruleId Rule identifier
     * @param reason Reason for reporting
     */
    function reportFalsePositive(address protectedContract, string calldata ruleId, string calldata reason) external;

    /**
     * @dev Emergency disable all protection
     */
    function emergencyDisable() external;

    /**
     * @dev Emergency enable all protection
     */
    function emergencyEnable() external;
}
