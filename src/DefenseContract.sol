// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./interfaces/IDefenseContract.sol";
import "./libraries/InputParser.sol";
import "./libraries/RuleChecker.sol";
import "./types/DataTypes.sol";

/**
 * @title DefenseContract
 * @dev Main defense contract for protecting smart contracts from attacks
 */
contract DefenseContract is IDefenseContract {
    using InputParser for bytes;
    using RuleChecker for DataTypes.ProtectionRule[];

    // Contract version
    string public constant VERSION = "1.0.0";

    // Owner and admins
    address public owner;
    mapping(address => bool) public admins;

    // Protection rules for each contract
    mapping(address => DataTypes.ProtectionRule[]) private protectionRules;
    mapping(address => mapping(string => uint256)) private ruleIndexes;
    mapping(address => DataTypes.ProtectionConfig) private protectionConfigs;
    mapping(address => mapping(string => DataTypes.RuleStats)) private ruleStats;

    // Mutation data storage
    mapping(address => mapping(bytes32 => DataTypes.MutationData[])) private mutationData;

    // Emergency controls
    bool public emergencyMode;
    bool public globalProtectionEnabled = true;

    // Rate limiting
    mapping(address => uint256) private lastCheckTime;
    uint256 public constant CHECK_COOLDOWN = 1 seconds;

    // Modifiers
    modifier onlyOwner() {
        if (msg.sender != owner) {
            console.log("DefenseContract: Unauthorized access attempt by:", msg.sender);
            revert DataTypes.UnauthorizedAccess(msg.sender);
        }
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != owner && !admins[msg.sender]) {
            console.log("DefenseContract: Non-admin access attempt by:", msg.sender);
            revert DataTypes.UnauthorizedAccess(msg.sender);
        }
        _;
    }

    modifier notEmergencyMode() {
        if (emergencyMode) {
            console.log("DefenseContract: Operation blocked due to emergency mode");
            revert DataTypes.EmergencyMode();
        }
        _;
    }

    modifier protectionEnabled(address protectedContract) {
        if (!globalProtectionEnabled || !protectionConfigs[protectedContract].enabled) {
            console.log("DefenseContract: Protection disabled for contract:", protectedContract);
            revert DataTypes.ProtectionDisabled(protectedContract);
        }
        _;
    }

    modifier rateLimited(address caller) {
        if (block.timestamp - lastCheckTime[caller] < CHECK_COOLDOWN) {
            console.log("DefenseContract: Rate limit exceeded for caller:", caller);
            revert DataTypes.CheckTimeout();
        }
        lastCheckTime[caller] = block.timestamp;
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
        console.log("DefenseContract: Contract deployed by owner:", msg.sender);
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @dev Main detection function
     */
    function detect(address protectedContract, bytes calldata inputData, address caller)
        external
        override
        protectionEnabled(protectedContract)
        rateLimited(caller)
        notEmergencyMode
        returns (DataTypes.DetectionResult memory result)
    {
        console.log("DefenseContract: detect() called for contract:", protectedContract);
        console.log("DefenseContract: Input data length:", inputData.length);
        console.log("DefenseContract: Caller:", caller);

        // Validate input
        if (protectedContract == address(0) || inputData.length == 0) {
            console.log("DefenseContract: Invalid parameters - zero address or empty input");
            revert DataTypes.InvalidParameters();
        }

        // Get protection rules
        DataTypes.ProtectionRule[] storage rules = protectionRules[protectedContract];
        console.log("DefenseContract: Found", rules.length, "protection rules for contract");

        if (rules.length == 0) {
            console.log("DefenseContract: No protection rules configured, allowing transaction");
            // No rules configured, allow transaction
            return DataTypes.DetectionResult({
                isAttack: false,
                triggeredRules: new string[](0),
                confidence: 0,
                reason: "No protection rules configured"
            });
        }

        // Check rules
        console.log("DefenseContract: Checking rules against input data...");
        result = RuleChecker.checkRules(rules, inputData, caller);
        console.log("DefenseContract: Rule check completed - isAttack:", result.isAttack);
        console.log("DefenseContract: Confidence level:", result.confidence);

        // Update statistics
        _updateRuleStats(protectedContract, result);

        // Emit events
        if (result.isAttack) {
            console.log("DefenseContract: ATTACK DETECTED! Triggered rules count:", result.triggeredRules.length);
            emit DataTypes.AttackDetected(protectedContract, caller, result.triggeredRules, result.confidence);

            // Use simple revert message instead of complex custom error
            revert("Attack detected");
        } else {
            console.log("DefenseContract: Transaction approved - no attack detected");
        }

        return result;
    }

    /**
     * @dev Add a new protection rule
     */
    function addRule(DataTypes.ProtectionRule calldata rule) external override onlyAdmin {
        console.log("DefenseContract: addRule() called for contract:", rule.protectedContract);
        console.log("DefenseContract: Rule ID:", rule.ruleId);

        if (!RuleChecker.validateRule(rule)) {
            console.log("DefenseContract: Rule validation failed");
            revert DataTypes.InvalidParameters();
        }

        address protectedContract = rule.protectedContract;
        string memory ruleId = rule.ruleId;

        // Check if rule already exists
        if (ruleIndexes[protectedContract][ruleId] > 0) {
            console.log("DefenseContract: Rule already exists:", ruleId);
            revert DataTypes.RuleAlreadyExists(ruleId);
        }

        // Check max rules limit
        DataTypes.ProtectionConfig storage config = protectionConfigs[protectedContract];
        if (config.maxRules > 0 && protectionRules[protectedContract].length >= config.maxRules) {
            console.log("DefenseContract: Max rules limit exceeded");
            revert DataTypes.MaxRulesExceeded(protectionRules[protectedContract].length, config.maxRules);
        }

        // Add rule
        protectionRules[protectedContract].push(rule);
        ruleIndexes[protectedContract][ruleId] = protectionRules[protectedContract].length;

        // Initialize rule statistics
        ruleStats[protectedContract][ruleId] =
            DataTypes.RuleStats({totalChecks: 0, detectedAttacks: 0, falsePositives: 0, lastTriggered: 0});

        console.log("DefenseContract: Rule added successfully. Total rules:", protectionRules[protectedContract].length);
        emit DataTypes.RuleAdded(protectedContract, ruleId, rule.originalTxHash);
    }

    /**
     * @dev Add multiple protection rules in batch
     */
    function addRules(DataTypes.ProtectionRule[] calldata rules) external override onlyAdmin {
        console.log("DefenseContract: addRules() called with", rules.length, "rules");

        for (uint256 i = 0; i < rules.length; i++) {
            console.log("DefenseContract: Adding rule", i + 1, "of", rules.length);
            // Create a copy to pass to addRule
            DataTypes.ProtectionRule memory rule = rules[i];
            _addSingleRule(rule);
        }

        console.log("DefenseContract: Batch rule addition completed");
    }

    /**
     * @dev Internal function to add a single rule (避免外部调用)
     */
    function _addSingleRule(DataTypes.ProtectionRule memory rule) internal {
        if (!RuleChecker.validateRule(rule)) {
            console.log("DefenseContract: Internal rule validation failed");
            revert DataTypes.InvalidParameters();
        }

        address protectedContract = rule.protectedContract;
        string memory ruleId = rule.ruleId;

        // Check if rule already exists
        if (ruleIndexes[protectedContract][ruleId] > 0) {
            console.log("DefenseContract: Internal - Rule already exists:", ruleId);
            revert DataTypes.RuleAlreadyExists(ruleId);
        }

        // Check max rules limit
        DataTypes.ProtectionConfig storage config = protectionConfigs[protectedContract];
        if (config.maxRules > 0 && protectionRules[protectedContract].length >= config.maxRules) {
            console.log("DefenseContract: Internal - Max rules limit exceeded");
            revert DataTypes.MaxRulesExceeded(protectionRules[protectedContract].length, config.maxRules);
        }

        // Add rule
        protectionRules[protectedContract].push(rule);
        ruleIndexes[protectedContract][ruleId] = protectionRules[protectedContract].length;

        // Initialize rule statistics
        ruleStats[protectedContract][ruleId] =
            DataTypes.RuleStats({totalChecks: 0, detectedAttacks: 0, falsePositives: 0, lastTriggered: 0});

        emit DataTypes.RuleAdded(protectedContract, ruleId, rule.originalTxHash);
    }

    /**
     * @dev Update an existing protection rule
     */
    function updateRule(string calldata ruleId, DataTypes.ProtectionRule calldata rule) external override onlyAdmin {
        console.log("DefenseContract: updateRule() called for rule:", ruleId);

        if (!RuleChecker.validateRule(rule)) {
            console.log("DefenseContract: Rule validation failed for update");
            revert DataTypes.InvalidParameters();
        }

        address protectedContract = rule.protectedContract;
        uint256 index = ruleIndexes[protectedContract][ruleId];

        if (index == 0) {
            console.log("DefenseContract: Rule not found for update:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        // Update rule (index is 1-based, array is 0-based)
        protectionRules[protectedContract][index - 1] = rule;
        console.log("DefenseContract: Rule updated successfully");

        emit DataTypes.RuleUpdated(protectedContract, ruleId, rule.isActive);
    }

    /**
     * @dev Remove a protection rule
     */
    function removeRule(address protectedContract, string calldata ruleId) external override onlyAdmin {
        console.log("DefenseContract: removeRule() called for rule:", ruleId);
        console.log("DefenseContract: Protected contract:", protectedContract);

        uint256 index = ruleIndexes[protectedContract][ruleId];

        if (index == 0) {
            console.log("DefenseContract: Rule not found for removal:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        // Remove rule (index is 1-based, array is 0-based)
        DataTypes.ProtectionRule[] storage rules = protectionRules[protectedContract];
        uint256 arrayIndex = index - 1;

        console.log("DefenseContract: Removing rule at index:", arrayIndex);
        console.log("DefenseContract: Total rules before removal:", rules.length);

        // Move last element to deleted spot
        if (arrayIndex < rules.length - 1) {
            rules[arrayIndex] = rules[rules.length - 1];
            // Update index mapping for moved rule
            ruleIndexes[protectedContract][rules[arrayIndex].ruleId] = index;
        }

        rules.pop();
        delete ruleIndexes[protectedContract][ruleId];
        delete ruleStats[protectedContract][ruleId];

        console.log("DefenseContract: Rule removed successfully. Total rules:", rules.length);
        emit DataTypes.RuleRemoved(protectedContract, ruleId);
    }

    /**
     * @dev Enable or disable a protection rule
     */
    function setRuleActive(address protectedContract, string calldata ruleId, bool isActive)
        external
        override
        onlyAdmin
    {
        console.log("DefenseContract: setRuleActive() called for rule:", ruleId);
        console.log("DefenseContract: Setting active status to:", isActive);

        uint256 index = ruleIndexes[protectedContract][ruleId];

        if (index == 0) {
            console.log("DefenseContract: Rule not found for activation:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        // Update rule active status (index is 1-based, array is 0-based)
        protectionRules[protectedContract][index - 1].isActive = isActive;
        console.log("DefenseContract: Rule active status updated successfully");

        emit DataTypes.RuleUpdated(protectedContract, ruleId, isActive);
    }

    /**
     * @dev Get all rules for a protected contract
     */
    function getRules(address protectedContract)
        external
        view
        override
        returns (DataTypes.ProtectionRule[] memory rules)
    {
        console.log("DefenseContract: getRules() called for contract:", protectedContract);
        console.log("DefenseContract: Returning", protectionRules[protectedContract].length, "rules");
        return protectionRules[protectedContract];
    }

    /**
     * @dev Get a specific rule by ID
     */
    function getRule(address protectedContract, string calldata ruleId)
        external
        view
        override
        returns (DataTypes.ProtectionRule memory rule)
    {
        console.log("DefenseContract: getRule() called for rule:", ruleId);

        uint256 index = ruleIndexes[protectedContract][ruleId];

        if (index == 0) {
            console.log("DefenseContract: Rule not found:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        return protectionRules[protectedContract][index - 1];
    }

    /**
     * @dev Get rule statistics
     */
    function getRuleStats(address protectedContract, string calldata ruleId)
        external
        view
        override
        returns (DataTypes.RuleStats memory stats)
    {
        console.log("DefenseContract: getRuleStats() called for rule:", ruleId);

        if (ruleIndexes[protectedContract][ruleId] == 0) {
            console.log("DefenseContract: Rule not found for stats:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        return ruleStats[protectedContract][ruleId];
    }

    /**
     * @dev Store mutation data from off-chain analysis
     */
    function storeMutationData(
        address protectedContract,
        bytes32 originalTxHash,
        DataTypes.MutationData[] calldata mutations
    ) external override onlyAdmin {
        console.log("DefenseContract: storeMutationData() called");
        console.log("DefenseContract: Protected contract:", protectedContract);
        console.log("DefenseContract: Storing", mutations.length, "mutations");

        // Store mutation data
        DataTypes.MutationData[] storage storedMutations = mutationData[protectedContract][originalTxHash];

        for (uint256 i = 0; i < mutations.length; i++) {
            storedMutations.push(mutations[i]);
        }

        console.log("DefenseContract: Mutation data stored successfully");
    }

    /**
     * @dev Get stored mutation data
     */
    function getMutationData(address protectedContract, bytes32 originalTxHash)
        external
        view
        override
        returns (DataTypes.MutationData[] memory mutations)
    {
        console.log("DefenseContract: getMutationData() called");
        console.log("DefenseContract: Protected contract:", protectedContract);

        DataTypes.MutationData[] memory result = mutationData[protectedContract][originalTxHash];
        console.log("DefenseContract: Returning", result.length, "mutations");

        return result;
    }

    /**
     * @dev Enable or disable protection for a contract
     */
    function setProtectionEnabled(address protectedContract, bool enabled) external override onlyAdmin {
        console.log("DefenseContract: setProtectionEnabled() called");
        console.log("DefenseContract: Protected contract:", protectedContract);
        console.log("DefenseContract: Setting enabled to:", enabled);

        protectionConfigs[protectedContract].enabled = enabled;
        console.log("DefenseContract: Protection status updated successfully");

        emit ProtectionStatusChanged(protectedContract, enabled);
    }

    /**
     * @dev Get protection configuration for a contract
     */
    function getProtectionConfig(address protectedContract)
        external
        view
        override
        returns (DataTypes.ProtectionConfig memory config)
    {
        console.log("DefenseContract: getProtectionConfig() called for contract:", protectedContract);
        return protectionConfigs[protectedContract];
    }

    /**
     * @dev Report a false positive
     */
    function reportFalsePositive(address protectedContract, string calldata ruleId, string calldata reason)
        external
        override
    {
        console.log("DefenseContract: reportFalsePositive() called");
        console.log("DefenseContract: Rule ID:", ruleId);
        console.log("DefenseContract: Reporter:", msg.sender);

        if (ruleIndexes[protectedContract][ruleId] == 0) {
            console.log("DefenseContract: Rule not found for false positive report:", ruleId);
            revert DataTypes.RuleNotFound(ruleId);
        }

        // Update statistics
        ruleStats[protectedContract][ruleId].falsePositives++;
        console.log("DefenseContract: False positive count updated");

        emit DataTypes.FalsePositiveReported(protectedContract, ruleId, msg.sender);
    }

    /**
     * @dev Emergency disable all protection
     */
    function emergencyDisable() external override onlyOwner {
        console.log("DefenseContract: emergencyDisable() called by:", msg.sender);

        emergencyMode = true;
        globalProtectionEnabled = false;

        console.log("DefenseContract: Emergency mode activated - all protection disabled");
        emit EmergencyModeActivated(msg.sender);
    }

    /**
     * @dev Emergency enable all protection
     */
    function emergencyEnable() external override onlyOwner {
        console.log("DefenseContract: emergencyEnable() called by:", msg.sender);

        emergencyMode = false;
        globalProtectionEnabled = true;

        console.log("DefenseContract: Emergency mode deactivated - protection enabled");
        emit EmergencyModeDeactivated(msg.sender);
    }

    /**
     * @dev Set protection configuration for a contract
     */
    function setProtectionConfig(address protectedContract, DataTypes.ProtectionConfig calldata config)
        external
        onlyAdmin
    {
        console.log("DefenseContract: setProtectionConfig() called");
        console.log("DefenseContract: Protected contract:", protectedContract);
        console.log("DefenseContract: Config enabled:", config.enabled);
        console.log("DefenseContract: Max rules:", config.maxRules);

        protectionConfigs[protectedContract] = config;
        console.log("DefenseContract: Protection config updated successfully");

        emit ProtectionConfigUpdated(protectedContract);
    }

    /**
     * @dev Add or remove admin
     */
    function setAdmin(address admin, bool isAdmin) external onlyOwner {
        console.log("DefenseContract: setAdmin() called");
        console.log("DefenseContract: Admin address:", admin);
        console.log("DefenseContract: Setting admin status to:", isAdmin);

        admins[admin] = isAdmin;
        console.log("DefenseContract: Admin status updated successfully");

        emit AdminStatusChanged(admin, isAdmin);
    }

    /**
     * @dev Transfer ownership
     */
    function transferOwnership(address newOwner) external onlyOwner {
        console.log("DefenseContract: transferOwnership() called");
        console.log("DefenseContract: Current owner:", owner);
        console.log("DefenseContract: New owner:", newOwner);

        if (newOwner == address(0)) {
            console.log("DefenseContract: Invalid new owner address - zero address");
            revert DataTypes.InvalidParameters();
        }

        address oldOwner = owner;
        owner = newOwner;
        admins[newOwner] = true;

        console.log("DefenseContract: Ownership transferred successfully");
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev Get contract statistics
     */
    function getContractStats(address protectedContract)
        external
        view
        returns (uint256 totalRules, uint256 activeRules, uint256 totalChecks, uint256 totalAttacks)
    {
        console.log("DefenseContract: getContractStats() called for contract:", protectedContract);

        DataTypes.ProtectionRule[] storage rules = protectionRules[protectedContract];
        totalRules = rules.length;

        for (uint256 i = 0; i < rules.length; i++) {
            if (rules[i].isActive) {
                activeRules++;
            }

            DataTypes.RuleStats storage stats = ruleStats[protectedContract][rules[i].ruleId];
            totalChecks += stats.totalChecks;
            totalAttacks += stats.detectedAttacks;
        }

        console.log("DefenseContract: Stats - Total rules:", totalRules);
        console.log("DefenseContract: Stats - Active rules:", activeRules);
        console.log("DefenseContract: Stats - Total checks:", totalChecks);
        console.log("DefenseContract: Stats - Total attacks:", totalAttacks);
    }

    /**
     * @dev Update rule statistics
     */
    function _updateRuleStats(address protectedContract, DataTypes.DetectionResult memory result) internal {
        console.log("DefenseContract: _updateRuleStats() called");
        console.log("DefenseContract: Updating stats for", result.triggeredRules.length, "rules");

        for (uint256 i = 0; i < result.triggeredRules.length; i++) {
            string memory ruleId = result.triggeredRules[i];
            DataTypes.RuleStats storage stats = ruleStats[protectedContract][ruleId];

            stats.totalChecks++;
            if (result.isAttack) {
                stats.detectedAttacks++;
                stats.lastTriggered = block.timestamp;
                console.log("DefenseContract: Attack detected for rule:", ruleId);
            }
        }

        console.log("DefenseContract: Rule statistics updated successfully");
    }

    // Events
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AdminStatusChanged(address indexed admin, bool isAdmin);
    event ProtectionStatusChanged(address indexed protectedContract, bool enabled);
    event ProtectionConfigUpdated(address indexed protectedContract);
    event EmergencyModeActivated(address indexed activator);
    event EmergencyModeDeactivated(address indexed deactivator);
}
