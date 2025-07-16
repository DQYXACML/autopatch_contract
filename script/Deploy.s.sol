// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/DefenseContract.sol";
import "../src/types/DataTypes.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying DefenseContract...");
        console.log("Deployer:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DefenseContract
        DefenseContract defenseContract = new DefenseContract();

        console.log("DefenseContract deployed at:", address(defenseContract));

        // Set up initial configuration
        DataTypes.ProtectionConfig memory config = DataTypes.ProtectionConfig({
            enabled: true,
            maxRules: 100,
            checkTimeout: 30,
            admins: new address[](1),
            emergencyMode: false
        });
        config.admins[0] = deployer;

        // Example: Set up protection for a sample contract
        // defenseContract.setProtectionConfig(TARGET_CONTRACT_ADDRESS, config);

        vm.stopBroadcast();

        console.log("Deployment completed successfully!");
        console.log("Contract owner:", defenseContract.owner());
        console.log("Global protection enabled:", defenseContract.globalProtectionEnabled());
    }
}
