// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/interfaces/IDefenseContract.sol";
import "../../src/types/DataTypes.sol";

/**
 * @title MockTarget
 * @dev Mock contract for testing the defense system
 */
contract MockTarget {
    IDefenseContract public defenseContract;

    // Storage variables for testing
    uint256 public value1;
    uint256 public value2;
    address public owner;
    mapping(address => uint256) public balances;
    mapping(uint256 => string) public data;
    bool public enabled;

    // Events
    event ValueChanged(uint256 indexed oldValue, uint256 indexed newValue);
    event BalanceUpdated(address indexed user, uint256 balance);
    event DataStored(uint256 indexed key, string value);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier protectedCall() {
        if (address(defenseContract) != address(0)) {
            // Call defense contract to check for attacks
            console.log("MockTarget: protectedCall");
            defenseContract.detect(address(this), msg.data, msg.sender);
        }
        _;
    }

    constructor(address _defenseContract) {
        defenseContract = IDefenseContract(_defenseContract);
        owner = msg.sender;
        value1 = 100;
        value2 = 200;
        enabled = true;
    }

    /**
     * @dev Set defense contract address
     */
    function setDefenseContract(address _defenseContract) external onlyOwner {
        defenseContract = IDefenseContract(_defenseContract);
    }

    /**
     * @dev Set value1 - protected function
     */
    function setValue1(uint256 _value) external protectedCall {
        uint256 oldValue = value1;
        value1 = _value;
        emit ValueChanged(oldValue, _value);
    }

    /**
     * @dev Set value2 - protected function
     */
    function setValue2(uint256 _value) external protectedCall {
        uint256 oldValue = value2;
        value2 = _value;
        emit ValueChanged(oldValue, _value);
    }

    /**
     * @dev Set balance - protected function
     */
    function setBalance(address _user, uint256 _balance) external protectedCall {
        balances[_user] = _balance;
        emit BalanceUpdated(_user, _balance);
    }

    /**
     * @dev Store data - protected function
     */
    function storeData(uint256 _key, string calldata _value) external protectedCall {
        data[_key] = _value;
        emit DataStored(_key, _value);
    }

    /**
     * @dev Transfer function - protected function
     */
    function transfer(address _to, uint256 _amount) external protectedCall {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;

        emit BalanceUpdated(msg.sender, balances[msg.sender]);
        emit BalanceUpdated(_to, balances[_to]);
    }

    /**
     * @dev Withdraw function - protected function
     */
    function withdraw(uint256 _amount) external protectedCall {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;

        payable(msg.sender).transfer(_amount);
        emit BalanceUpdated(msg.sender, balances[msg.sender]);
    }

    /**
     * @dev Admin function - protected function
     */
    function adminFunction(bytes calldata _data) external protectedCall onlyOwner {
        // Execute admin data
        (bool success,) = address(this).call(_data);
        require(success, "Admin function failed");
    }

    /**
     * @dev Emergency function - protected function
     */
    function emergency() external protectedCall onlyOwner {
        enabled = false;
        // Emergency logic here
    }

    /**
     * @dev Multiple parameter function - protected function
     */
    function multipleParams(uint256 _value1, address _addr, string calldata _str, bool _flag) external protectedCall {
        value1 = _value1;
        owner = _addr;
        data[0] = _str;
        enabled = _flag;
    }

    /**
     * @dev Fallback function - protected
     */
    fallback() external payable protectedCall {
        // Fallback logic
    }

    /**
     * @dev Receive function - protected
     */
    receive() external payable protectedCall {
        balances[msg.sender] += msg.value;
        emit BalanceUpdated(msg.sender, balances[msg.sender]);
    }

    /**
     * @dev Get contract state for testing
     */
    function getState() external view returns (uint256 _value1, uint256 _value2, address _owner, bool _enabled) {
        return (value1, value2, owner, enabled);
    }
}
