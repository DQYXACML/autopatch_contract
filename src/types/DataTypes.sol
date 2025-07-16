// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DataTypes
 * @dev Defines all data structures for the defense system
 */
library DataTypes {
    /**
     * @dev Enum for different check types
     */
    enum CheckType {
        EXACT, // Exact match
        RANGE, // Value within range
        PATTERN, // Pattern matching
        DELTA // Delta comparison

    }

    /**
     * @dev Enum for storage slot types
     */
    enum SlotType {
        SIMPLE, // Simple variable
        MAPPING, // Mapping slot
        ARRAY, // Array slot
        STRUCT // Struct slot

    }

    /**
     * @dev Parameter protection rule for input validation
     */
    struct ParameterRule {
        uint256 index; // Parameter index
        string paramType; // Parameter type (uint256, address, etc.)
        bytes32 originalValue; // Original value hash
        bytes32 modifiedValue; // Modified value hash
        uint256 minValue; // Minimum allowed value
        uint256 maxValue; // Maximum allowed value
        CheckType checkType; // Type of check to perform
        bool isActive; // Whether rule is active
    }

    /**
     * @dev Input protection rule for function calls
     */
    struct InputRule {
        bytes4 functionSelector; // Function selector
        string functionName; // Function name
        bytes originalInput; // Original input data
        bytes modifiedInput; // Modified input data
        ParameterRule[] parameters; // Parameter rules
        bytes32 inputHash; // Input hash for quick lookup
        bool isActive; // Whether rule is active
    }

    /**
     * @dev Storage protection rule for state variables
     */
    struct StorageRule {
        address contractAddress; // Contract address to check
        bytes32 storageSlot; // Storage slot to check
        bytes32 originalValue; // Original value
        bytes32 modifiedValue; // Modified value
        uint256 minValue; // Minimum allowed value
        uint256 maxValue; // Maximum allowed value
        CheckType checkType; // Type of check to perform
        SlotType slotType; // Type of storage slot
        bool isActive; // Whether rule is active
    }

    /**
     * @dev Complete protection rule combining input and storage rules
     */
    struct ProtectionRule {
        string ruleId; // Unique rule identifier
        bytes32 originalTxHash; // Original attack transaction hash
        address protectedContract; // Contract being protected
        uint256 similarity; // Similarity threshold (basis points)
        InputRule[] inputRules; // Input protection rules
        StorageRule[] storageRules; // Storage protection rules
        uint256 createdAt; // Creation timestamp
        bool isActive; // Whether rule is active
    }

    /**
     * @dev Mutation data for storing attack patterns
     */
    struct MutationData {
        string mutationId; // Unique mutation identifier
        bytes inputData; // Mutated input data
        StorageChange[] storageChanges; // Storage changes
        uint256 similarity; // Similarity score (basis points)
        bool isSuccessful; // Whether mutation was successful
        uint256 executionTime; // Execution time in milliseconds
    }

    /**
     * @dev Storage change data
     */
    struct StorageChange {
        bytes32 slot; // Storage slot
        bytes32 newValue; // New value
    }

    /**
     * @dev Detection result
     */
    struct DetectionResult {
        bool isAttack; // Whether an attack was detected
        string[] triggeredRules; // List of triggered rule IDs
        uint256 confidence; // Confidence score (basis points)
        string reason; // Reason for detection
    }

    /**
     * @dev Rule statistics
     */
    struct RuleStats {
        uint256 totalChecks; // Total number of checks
        uint256 detectedAttacks; // Number of detected attacks
        uint256 falsePositives; // Number of false positives
        uint256 lastTriggered; // Last time rule was triggered
    }

    /**
     * @dev Contract protection configuration
     */
    struct ProtectionConfig {
        bool enabled; // Whether protection is enabled
        uint256 maxRules; // Maximum number of rules per contract
        uint256 checkTimeout; // Timeout for checks in seconds
        address[] admins; // List of admin addresses
        bool emergencyMode; // Emergency mode flag
    }

    /**
     * @dev Events for rule management
     */
    event RuleAdded(address indexed protectedContract, string indexed ruleId, bytes32 originalTxHash);

    event RuleTriggered(
        address indexed protectedContract, address indexed caller, string indexed ruleId, bytes inputData
    );

    event RuleUpdated(address indexed protectedContract, string indexed ruleId, bool isActive);

    event RuleRemoved(address indexed protectedContract, string indexed ruleId);

    event AttackDetected(
        address indexed protectedContract, address indexed attacker, string[] triggeredRules, uint256 confidence
    );

    event FalsePositiveReported(address indexed protectedContract, string indexed ruleId, address reporter);

    /**
     * @dev Custom Errors - 注意：错误名称与事件不同以避免冲突
     */
    error RuleNotFound(string ruleId);
    error RuleAlreadyExists(string ruleId);
    error UnauthorizedAccess(address caller);
    error ProtectionDisabled(address protectedContract);
    error InvalidParameters();
    error AttackDetectionTriggered(string[] rules, uint256 confidence); // 重命名以避免与事件冲突
    error CheckTimeout();
    error EmergencyMode();
    error MaxRulesExceeded(uint256 current, uint256 max);
}
