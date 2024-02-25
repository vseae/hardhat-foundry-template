// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";

contract DemoUpgradeable is ERC20Upgradeable {
    uint256 internal value;
    uint256 internal version;

    function initialize(string memory name, string memory symbol) public initializer {
        __ERC20_init(name, symbol);
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
