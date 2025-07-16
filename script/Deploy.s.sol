// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DefenseContract.sol";
import "../src/types/DataTypes.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("=== Deploying to Sepolia Network ===");
        console.log("Deployer address:", deployer);

        // Check deployer balance
        uint256 balance = deployer.balance;
        console.log("Deployer balance:", balance, "wei");
        console.log("Deployer balance:", balance / 1e18, "ETH");

        // Ensure we have enough ETH for deployment
        require(balance > 0.01 ether, "Deployer needs at least 0.01 ETH for gas fees");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DefenseContract
        console.log("Deploying DefenseContract...");
        DefenseContract defenseContract = new DefenseContract();

        vm.stopBroadcast();

        // Print deployment information
        console.log("=== Deployment Successful ===");
        console.log("DefenseContract deployed at:", address(defenseContract));
        console.log("Transaction broadcasted to Sepolia network");

        // Verify deployment
        console.log("=== Verifying Deployment ===");
        require(address(defenseContract) != address(0), "Contract deployment failed");
        require(defenseContract.owner() == deployer, "Owner not set correctly");
        require(keccak256(bytes(defenseContract.VERSION())) == keccak256(bytes("1.0.0")), "Version check failed");

        console.log("Contract owner:", defenseContract.owner());
        console.log("Global protection enabled:", defenseContract.globalProtectionEnabled());
        console.log("Contract version:", defenseContract.VERSION());
        console.log("Emergency mode:", defenseContract.emergencyMode());
        console.log("Verification passed!");

        // Set up initial configuration
        vm.startBroadcast(deployerPrivateKey);

        console.log("Setting up initial configuration...");

        // Set admin status for deployer (already done in constructor, but verify)
        if (!defenseContract.admins(deployer)) {
            defenseContract.setAdmin(deployer, true);
            console.log("Admin status set for deployer");
        } else {
            console.log("Deployer already has admin status");
        }

        vm.stopBroadcast();

        console.log("=== Deployment Completed Successfully! ===");
        console.log("");
        console.log("IMPORTANT: Add this to your .env file for testing:");
        console.log("DEFENSE_CONTRACT_ADDRESS=", address(defenseContract));
        console.log("");
        console.log("Contract is now deployed on Sepolia at:", address(defenseContract));
        console.log("You can now run tests with: forge test --fork-url $SEPOLIA_RPC_URL");
    }
}
