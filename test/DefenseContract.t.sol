// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/DefenseContract.sol";
import "../src/types/DataTypes.sol";
import "./mocks/MockTarget.sol";

contract DefenseContractTest is Test {
    DefenseContract public defenseContract;
    MockTarget public mockTarget;

    address public owner = address(1);
    address public admin = address(2);
    address public user = address(3);
    address public attacker = address(4);

    // Test constants
    string constant TEST_RULE_ID = "test_rule_1";
    bytes32 constant TEST_TX_HASH = keccak256("test_tx");
    uint256 constant TEST_SIMILARITY = 8000; // 80%

    function setUp() public {
        vm.startPrank(owner);

        // Deploy defense contract
        defenseContract = new DefenseContract();

        // Deploy mock target
        mockTarget = new MockTarget(address(defenseContract));

        // Set up admin
        defenseContract.setAdmin(admin, true);

        // Enable protection for mock target
        defenseContract.setProtectionEnabled(address(mockTarget), true);

        vm.stopPrank();
    }

    function testInitialState() public {
        assertEq(defenseContract.owner(), owner);
        assertTrue(defenseContract.admins(owner));
        assertTrue(defenseContract.admins(admin));
        assertTrue(defenseContract.globalProtectionEnabled());
        assertFalse(defenseContract.emergencyMode());
    }

    function testAddInputRule() public {
        vm.startPrank(admin);

        // Create input rule
        DataTypes.ParameterRule[] memory parameters = new DataTypes.ParameterRule[](1);
        parameters[0] = DataTypes.ParameterRule({
            index: 0,
            paramType: "uint256",
            originalValue: bytes32(uint256(100)),
            modifiedValue: bytes32(uint256(999)),
            minValue: 900,
            maxValue: 1100,
            checkType: DataTypes.CheckType.RANGE,
            isActive: true
        });

        DataTypes.InputRule[] memory inputRules = new DataTypes.InputRule[](1);
        inputRules[0] = DataTypes.InputRule({
            functionSelector: bytes4(keccak256("setValue1(uint256)")),
            functionName: "setValue1",
            originalInput: abi.encodeWithSelector(bytes4(keccak256("setValue1(uint256)")), 100),
            modifiedInput: abi.encodeWithSelector(bytes4(keccak256("setValue1(uint256)")), 999),
            parameters: parameters,
            inputHash: keccak256("test_input"),
            isActive: true
        });

        DataTypes.ProtectionRule memory rule = DataTypes.ProtectionRule({
            ruleId: TEST_RULE_ID,
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules,
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule);

        // Verify rule was added
        DataTypes.ProtectionRule[] memory rules = defenseContract.getRules(address(mockTarget));
        assertEq(rules.length, 1);
        assertEq(rules[0].ruleId, TEST_RULE_ID);

        vm.stopPrank();
    }

    function testAddStorageRule() public {
        vm.startPrank(admin);

        // Create storage rule
        DataTypes.StorageRule[] memory storageRules = new DataTypes.StorageRule[](1);
        storageRules[0] = DataTypes.StorageRule({
            contractAddress: address(mockTarget),
            storageSlot: bytes32(uint256(0)), // value1 slot
            originalValue: bytes32(uint256(100)),
            modifiedValue: bytes32(uint256(999)),
            minValue: 900,
            maxValue: 1100,
            checkType: DataTypes.CheckType.RANGE,
            slotType: DataTypes.SlotType.SIMPLE,
            isActive: true
        });

        DataTypes.ProtectionRule memory rule = DataTypes.ProtectionRule({
            ruleId: TEST_RULE_ID,
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: new DataTypes.InputRule[](0),
            storageRules: storageRules,
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule);

        // Verify rule was added
        DataTypes.ProtectionRule[] memory rules = defenseContract.getRules(address(mockTarget));
        assertEq(rules.length, 1);
        assertEq(rules[0].storageRules.length, 1);

        vm.stopPrank();
    }

    function testDetectAttackWithInputRule() public {
        // Add input rule first
        testAddInputRule();

        vm.startPrank(attacker);

        // This should trigger the attack detection
        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999);

        vm.stopPrank();
    }

    function testDetectAttackWithStorageRule() public {
        // Add storage rule first
        testAddStorageRule();

        vm.startPrank(attacker);

        // Set value1 to trigger storage rule
        mockTarget.setValue1(999);

        // This should trigger the attack detection on next call
        vm.expectRevert("Attack detected");
        mockTarget.setValue2(500);

        vm.stopPrank();
    }

    function testNormalTransactionPasses() public {
        // Add input rule first
        testAddInputRule();

        vm.startPrank(user);

        // This should pass (different from attack pattern)
        mockTarget.setValue1(50);

        // Verify the value was set
        assertEq(mockTarget.value1(), 50);

        vm.stopPrank();
    }

    function testMultipleRules() public {
        vm.startPrank(admin);

        // Add first rule
        testAddInputRule();

        // Add second rule
        DataTypes.ParameterRule[] memory parameters = new DataTypes.ParameterRule[](1);
        parameters[0] = DataTypes.ParameterRule({
            index: 0,
            paramType: "uint256",
            originalValue: bytes32(uint256(200)),
            modifiedValue: bytes32(uint256(888)),
            minValue: 800,
            maxValue: 900,
            checkType: DataTypes.CheckType.RANGE,
            isActive: true
        });

        DataTypes.InputRule[] memory inputRules = new DataTypes.InputRule[](1);
        inputRules[0] = DataTypes.InputRule({
            functionSelector: bytes4(keccak256("setValue2(uint256)")),
            functionName: "setValue2",
            originalInput: abi.encodeWithSelector(bytes4(keccak256("setValue2(uint256)")), 200),
            modifiedInput: abi.encodeWithSelector(bytes4(keccak256("setValue2(uint256)")), 888),
            parameters: parameters,
            inputHash: keccak256("test_input_2"),
            isActive: true
        });

        DataTypes.ProtectionRule memory rule2 = DataTypes.ProtectionRule({
            ruleId: "test_rule_2",
            originalTxHash: keccak256("test_tx_2"),
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules,
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule2);

        // Verify both rules exist
        DataTypes.ProtectionRule[] memory rules = defenseContract.getRules(address(mockTarget));
        assertEq(rules.length, 2);

        vm.stopPrank();

        // Test that both rules work
        vm.startPrank(attacker);

        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999); // Should trigger rule 1

        vm.expectRevert("Attack detected");
        mockTarget.setValue2(888); // Should trigger rule 2

        vm.stopPrank();
    }

    function testRuleManagement() public {
        vm.startPrank(admin);

        // Add rule
        testAddInputRule();

        // Disable rule
        defenseContract.setRuleActive(address(mockTarget), TEST_RULE_ID, false);

        // Verify rule is disabled
        DataTypes.ProtectionRule memory rule = defenseContract.getRule(address(mockTarget), TEST_RULE_ID);
        assertFalse(rule.isActive);

        // Enable rule
        defenseContract.setRuleActive(address(mockTarget), TEST_RULE_ID, true);

        // Verify rule is enabled
        rule = defenseContract.getRule(address(mockTarget), TEST_RULE_ID);
        assertTrue(rule.isActive);

        // Remove rule
        defenseContract.removeRule(address(mockTarget), TEST_RULE_ID);

        // Verify rule is removed
        DataTypes.ProtectionRule[] memory rules = defenseContract.getRules(address(mockTarget));
        assertEq(rules.length, 0);

        vm.stopPrank();
    }

    function testEmergencyMode() public {
        // Add rule first
        testAddInputRule();

        vm.startPrank(owner);

        // Activate emergency mode
        defenseContract.emergencyDisable();

        assertTrue(defenseContract.emergencyMode());
        assertFalse(defenseContract.globalProtectionEnabled());

        vm.stopPrank();

        // Attack should pass in emergency mode
        vm.startPrank(attacker);

        mockTarget.setValue1(999); // Should not revert
        assertEq(mockTarget.value1(), 999);

        vm.stopPrank();

        // Deactivate emergency mode
        vm.startPrank(owner);
        defenseContract.emergencyEnable();
        vm.stopPrank();

        // Attack should be blocked again
        vm.startPrank(attacker);
        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999);
        vm.stopPrank();
    }

    function testRuleStats() public {
        // Add rule first
        testAddInputRule();

        vm.startPrank(attacker);

        // Trigger attack detection
        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999);

        vm.stopPrank();

        // Check rule statistics
        DataTypes.RuleStats memory stats = defenseContract.getRuleStats(address(mockTarget), TEST_RULE_ID);
        assertEq(stats.detectedAttacks, 1);
        assertGt(stats.lastTriggered, 0);
    }

    function testFalsePositiveReporting() public {
        // Add rule first
        testAddInputRule();

        vm.startPrank(user);

        // Report false positive
        defenseContract.reportFalsePositive(address(mockTarget), TEST_RULE_ID, "Not an attack");

        vm.stopPrank();

        // Check statistics
        DataTypes.RuleStats memory stats = defenseContract.getRuleStats(address(mockTarget), TEST_RULE_ID);
        assertEq(stats.falsePositives, 1);
    }

    function testStoreMutationData() public {
        vm.startPrank(admin);

        // Create mutation data
        DataTypes.MutationData[] memory mutations = new DataTypes.MutationData[](2);

        DataTypes.StorageChange[] memory changes1 = new DataTypes.StorageChange[](1);
        changes1[0] = DataTypes.StorageChange({slot: bytes32(uint256(0)), newValue: bytes32(uint256(999))});

        mutations[0] = DataTypes.MutationData({
            mutationId: "mutation_1",
            inputData: abi.encodeWithSelector(bytes4(keccak256("setValue1(uint256)")), 999),
            storageChanges: changes1,
            similarity: 8500,
            isSuccessful: true,
            executionTime: 150
        });

        DataTypes.StorageChange[] memory changes2 = new DataTypes.StorageChange[](1);
        changes2[0] = DataTypes.StorageChange({slot: bytes32(uint256(1)), newValue: bytes32(uint256(888))});

        mutations[1] = DataTypes.MutationData({
            mutationId: "mutation_2",
            inputData: abi.encodeWithSelector(bytes4(keccak256("setValue2(uint256)")), 888),
            storageChanges: changes2,
            similarity: 9000,
            isSuccessful: true,
            executionTime: 200
        });

        // Store mutation data
        defenseContract.storeMutationData(address(mockTarget), TEST_TX_HASH, mutations);

        // Retrieve and verify
        DataTypes.MutationData[] memory retrievedMutations =
            defenseContract.getMutationData(address(mockTarget), TEST_TX_HASH);
        assertEq(retrievedMutations.length, 2);
        assertEq(retrievedMutations[0].mutationId, "mutation_1");
        assertEq(retrievedMutations[1].mutationId, "mutation_2");

        vm.stopPrank();
    }

    function testAccessControl() public {
        // Non-admin should not be able to add rules
        vm.startPrank(user);

        DataTypes.ProtectionRule memory rule = DataTypes.ProtectionRule({
            ruleId: "unauthorized_rule",
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: new DataTypes.InputRule[](0),
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        vm.expectRevert();
        defenseContract.addRule(rule);

        vm.stopPrank();

        // Only owner should be able to use emergency functions
        vm.startPrank(user);

        vm.expectRevert();
        defenseContract.emergencyDisable();

        vm.stopPrank();
    }

    function testRateLimiting() public {
        // Add rule first
        testAddInputRule();

        vm.startPrank(user);

        // First call should work
        mockTarget.setValue1(50);

        // Second call immediately should fail due to rate limiting
        vm.expectRevert();
        mockTarget.setValue1(60);

        vm.stopPrank();
    }

    function testGetContractStats() public {
        // Add multiple rules
        testAddInputRule();
        testAddStorageRule();

        // Get stats
        (uint256 totalRules, uint256 activeRules, uint256 totalChecks, uint256 totalAttacks) =
            defenseContract.getContractStats(address(mockTarget));

        assertEq(totalRules, 2);
        assertEq(activeRules, 2);
        // totalChecks and totalAttacks depend on previous test execution
    }
}
