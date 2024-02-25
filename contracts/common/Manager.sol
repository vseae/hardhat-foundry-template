// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

abstract contract Manager is AccessControl, Ownable, Pausable {
    bool public live;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    modifier onlyLive() {
        require(live, "Manager: not live");
        _;
    }
    modifier isAuthorized() {
        require(hasRole(OPERATOR_ROLE, msg.sender) || owner() == msg.sender, "Manager: caller is not authorized");
        _;
    }

    function setLive(bool _live) external virtual isAuthorized {
        live = _live;
    }

    function grantRole(bytes32 role, address account) public virtual override onlyOwner {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual override onlyOwner {
        _revokeRole(role, account);
    }

    function grantOperatorRole(address account) external virtual onlyOwner {
        _grantRole(OPERATOR_ROLE, account);
    }

    function revokeOperatorRole(address account) external virtual onlyOwner {
        _revokeRole(OPERATOR_ROLE, account);
    }

    function grantMinterRole(address account) external virtual onlyOwner {
        _grantRole(MINTER_ROLE, account);
    }

    function revokeMinterRole(address account) external virtual onlyOwner {
        _revokeRole(MINTER_ROLE, account);
    }

    function grantBurnerRole(address account) external virtual onlyOwner {
        _grantRole(BURNER_ROLE, account);
    }

    function revokeBurnerRole(address account) external virtual onlyOwner {
        _revokeRole(BURNER_ROLE, account);
    }

    function pause() external virtual isAuthorized {
        _pause();
    }

    function unpause() external virtual isAuthorized {
        _unpause();
    }
}
