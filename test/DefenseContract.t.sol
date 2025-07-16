// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/DefenseContract.sol";
import "../src/types/DataTypes.sol";
import "./mocks/MockTarget.sol";

contract DefenseContractTest is Test {
    DefenseContract public defenseContract;
    MockTarget public mockTarget;

    address public owner;
    address public admin = address(2);
    address public user = address(3);
    address public attacker = address(4);

    // Test constants
    string constant TEST_RULE_ID = "test_rule_1";
    bytes32 constant TEST_TX_HASH = keccak256("test_tx");
    uint256 constant TEST_SIMILARITY = 8000; // 80%

    function setUp() public {
        // Create fork of Sepolia network
        string memory rpcUrl = vm.envString("SEPOLIA_RPC_URL");
        uint256 forkId = vm.createSelectFork(rpcUrl);
        console.log("Created Sepolia fork with ID:", forkId);

        // Get deployed contract address from environment
        string memory deployedAddress = vm.envString("DEFENSE_CONTRACT_ADDRESS");
        require(bytes(deployedAddress).length > 0, "DEFENSE_CONTRACT_ADDRESS not set in .env");

        address contractAddress = vm.parseAddress(deployedAddress);
        require(contractAddress != address(0), "Invalid DEFENSE_CONTRACT_ADDRESS");

        // Connect to deployed contract
        defenseContract = DefenseContract(contractAddress);

        // Get the actual owner from the deployed contract
        owner = defenseContract.owner();
        console.log("Connected to deployed DefenseContract at:", address(defenseContract));
        console.log("Contract owner:", owner);
        console.log("Contract version:", defenseContract.VERSION());

        // Fund test accounts with ETH for gas fees
        vm.deal(owner, 10 ether);
        vm.deal(admin, 5 ether);
        vm.deal(user, 5 ether);
        vm.deal(attacker, 5 ether);

        // Set up test environment
        vm.startPrank(owner);

        // Deploy mock target for testing (this will be deployed on the fork)
        mockTarget = new MockTarget(address(defenseContract));
        console.log("MockTarget deployed at:", address(mockTarget));

        // Set up admin if not already set
        if (!defenseContract.admins(admin)) {
            defenseContract.setAdmin(admin, true);
            console.log("Admin status granted to:", admin);
        }

        // Enable protection for mock target
        defenseContract.setProtectionEnabled(address(mockTarget), true);
        console.log("Protection enabled for MockTarget");

        vm.stopPrank();

        console.log("=== Test setup completed on Sepolia fork ===");
    }

    function testInitialState() public {
        console.log("Running testInitialState...");

        assertEq(defenseContract.owner(), owner);
        assertTrue(defenseContract.admins(owner));
        assertTrue(defenseContract.globalProtectionEnabled());
        assertFalse(defenseContract.emergencyMode());

        console.log("Initial state test passed");
    }

    function testAddInputRule() public {
        console.log("Running testAddInputRule...");

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

        console.log("Input rule added successfully");

        vm.stopPrank();
    }

    function testAddStorageRule() public {
        console.log("Running testAddStorageRule...");

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
            ruleId: "storage_rule_1",
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
        assertGt(rules.length, 0);

        console.log("Storage rule added successfully");

        vm.stopPrank();
    }

    function testDetectAttackWithInputRule() public {
        console.log("Running testDetectAttackWithInputRule...");

        // Add input rule first
        testAddInputRule();

        vm.startPrank(attacker);

        // This should trigger the attack detection
        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999);

        console.log("Attack detection with input rule working");

        vm.stopPrank();
    }

    function testNormalTransactionPasses() public {
        console.log("Running testNormalTransactionPasses...");

        // Add input rule first
        testAddInputRule();

        vm.startPrank(user);

        // This should pass (different from attack pattern)
        mockTarget.setValue1(50);

        // Verify the value was set
        assertEq(mockTarget.value1(), 50);

        console.log("Normal transaction passes");

        vm.stopPrank();
    }

    function testMultipleRules() public {
        console.log("Running testMultipleRules...");

        vm.startPrank(admin);

        // Clear existing rules by getting current count and removing them
        DataTypes.ProtectionRule[] memory existingRules = defenseContract.getRules(address(mockTarget));
        for (uint256 i = 0; i < existingRules.length; i++) {
            defenseContract.removeRule(address(mockTarget), existingRules[i].ruleId);
        }

        // Add first rule
        DataTypes.ParameterRule[] memory parameters1 = new DataTypes.ParameterRule[](1);
        parameters1[0] = DataTypes.ParameterRule({
            index: 0,
            paramType: "uint256",
            originalValue: bytes32(uint256(100)),
            modifiedValue: bytes32(uint256(999)),
            minValue: 900,
            maxValue: 1100,
            checkType: DataTypes.CheckType.RANGE,
            isActive: true
        });

        DataTypes.InputRule[] memory inputRules1 = new DataTypes.InputRule[](1);
        inputRules1[0] = DataTypes.InputRule({
            functionSelector: bytes4(keccak256("setValue1(uint256)")),
            functionName: "setValue1",
            originalInput: abi.encodeWithSelector(bytes4(keccak256("setValue1(uint256)")), 100),
            modifiedInput: abi.encodeWithSelector(bytes4(keccak256("setValue1(uint256)")), 999),
            parameters: parameters1,
            inputHash: keccak256("test_input_1"),
            isActive: true
        });

        DataTypes.ProtectionRule memory rule1 = DataTypes.ProtectionRule({
            ruleId: "multi_test_rule_1",
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules1,
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule1);

        // Add second rule
        DataTypes.ParameterRule[] memory parameters2 = new DataTypes.ParameterRule[](1);
        parameters2[0] = DataTypes.ParameterRule({
            index: 0,
            paramType: "uint256",
            originalValue: bytes32(uint256(200)),
            modifiedValue: bytes32(uint256(888)),
            minValue: 800,
            maxValue: 900,
            checkType: DataTypes.CheckType.RANGE,
            isActive: true
        });

        DataTypes.InputRule[] memory inputRules2 = new DataTypes.InputRule[](1);
        inputRules2[0] = DataTypes.InputRule({
            functionSelector: bytes4(keccak256("setValue2(uint256)")),
            functionName: "setValue2",
            originalInput: abi.encodeWithSelector(bytes4(keccak256("setValue2(uint256)")), 200),
            modifiedInput: abi.encodeWithSelector(bytes4(keccak256("setValue2(uint256)")), 888),
            parameters: parameters2,
            inputHash: keccak256("test_input_2"),
            isActive: true
        });

        DataTypes.ProtectionRule memory rule2 = DataTypes.ProtectionRule({
            ruleId: "multi_test_rule_2",
            originalTxHash: keccak256("test_tx_2"),
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules2,
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

        console.log("Multiple rules working correctly");

        vm.stopPrank();
    }

    function testRuleManagement() public {
        console.log("Running testRuleManagement...");

        vm.startPrank(admin);

        // Clear existing rules first
        DataTypes.ProtectionRule[] memory existingRules = defenseContract.getRules(address(mockTarget));
        for (uint256 i = 0; i < existingRules.length; i++) {
            defenseContract.removeRule(address(mockTarget), existingRules[i].ruleId);
        }

        // Add rule
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
            ruleId: "management_test_rule",
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules,
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule);

        // Disable rule
        defenseContract.setRuleActive(address(mockTarget), "management_test_rule", false);

        // Verify rule is disabled
        DataTypes.ProtectionRule memory retrievedRule =
            defenseContract.getRule(address(mockTarget), "management_test_rule");
        assertFalse(retrievedRule.isActive);

        // Enable rule
        defenseContract.setRuleActive(address(mockTarget), "management_test_rule", true);

        // Verify rule is enabled
        retrievedRule = defenseContract.getRule(address(mockTarget), "management_test_rule");
        assertTrue(retrievedRule.isActive);

        // Remove rule
        defenseContract.removeRule(address(mockTarget), "management_test_rule");

        // Verify rule is removed
        DataTypes.ProtectionRule[] memory rules = defenseContract.getRules(address(mockTarget));
        assertEq(rules.length, 0);

        console.log("Rule management working correctly");

        vm.stopPrank();
    }

    function testEmergencyMode() public {
        console.log("Running testEmergencyMode...");

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

        console.log("Emergency mode working correctly");
    }

    function testRuleStats() public {
        console.log("Running testRuleStats...");

        // Clear existing rules first
        vm.startPrank(admin);
        DataTypes.ProtectionRule[] memory existingRules = defenseContract.getRules(address(mockTarget));
        for (uint256 i = 0; i < existingRules.length; i++) {
            defenseContract.removeRule(address(mockTarget), existingRules[i].ruleId);
        }

        // Add fresh rule for stats testing
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
            ruleId: "stats_test_rule",
            originalTxHash: TEST_TX_HASH,
            protectedContract: address(mockTarget),
            similarity: TEST_SIMILARITY,
            inputRules: inputRules,
            storageRules: new DataTypes.StorageRule[](0),
            createdAt: block.timestamp,
            isActive: true
        });

        defenseContract.addRule(rule);
        vm.stopPrank();

        vm.startPrank(attacker);

        // Trigger attack detection
        vm.expectRevert("Attack detected");
        mockTarget.setValue1(999);

        vm.stopPrank();

        // Check rule statistics
        DataTypes.RuleStats memory stats = defenseContract.getRuleStats(address(mockTarget), "stats_test_rule");
        assertEq(stats.detectedAttacks, 1);
        assertGt(stats.lastTriggered, 0);

        console.log("Rule statistics working correctly");
    }

    function testFalsePositiveReporting() public {
        console.log("Running testFalsePositiveReporting...");

        // Add rule first
        testAddInputRule();

        vm.startPrank(user);

        // Report false positive
        defenseContract.reportFalsePositive(address(mockTarget), TEST_RULE_ID, "Not an attack");

        vm.stopPrank();

        // Check statistics
        DataTypes.RuleStats memory stats = defenseContract.getRuleStats(address(mockTarget), TEST_RULE_ID);
        assertEq(stats.falsePositives, 1);

        console.log("False positive reporting working correctly");
    }

    function testStoreMutationData() public {
        console.log("Running testStoreMutationData...");

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

        console.log("Mutation data storage working correctly");

        vm.stopPrank();
    }

    function testAccessControl() public {
        console.log("Running testAccessControl...");

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

        console.log("Access control working correctly");

        vm.stopPrank();
    }

    function testGetContractStats() public {
        console.log("Running testGetContractStats...");

        // Clear existing rules first
        vm.startPrank(admin);
        DataTypes.ProtectionRule[] memory existingRules = defenseContract.getRules(address(mockTarget));
        for (uint256 i = 0; i < existingRules.length; i++) {
            defenseContract.removeRule(address(mockTarget), existingRules[i].ruleId);
        }
        vm.stopPrank();

        // Add test rules
        testAddInputRule();
        testAddStorageRule();

        // Get stats
        (uint256 totalRules, uint256 activeRules, uint256 totalChecks, uint256 totalAttacks) =
            defenseContract.getContractStats(address(mockTarget));

        assertGt(totalRules, 0);
        assertGt(activeRules, 0);

        console.log("Total rules:", totalRules);
        console.log("Active rules:", activeRules);
        console.log("Contract stats working correctly");
    }
}
