// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/// @notice The contract add user to the contract in case if signature passes
contract SigTest is Ownable, AccessControl {
    ///@notice Hash of minter role for access control
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*****
     * SIGNATURE STORAGE
     *****/

    mapping(address => address) public signatures;

    modifier operatorOnly() {
        require(
            hasRole(OPERATOR_ROLE, _msgSender()),
            "Caller is not an operator"
        );
        _;
    }

    /*****
     * CONSTRUCTOR AND ADMIN FUNCTIONS
     *****/

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(OPERATOR_ROLE, _msgSender());
    }

    ///@notice Sets operator role
    ///@param _operator Address that will be set as operator
    function setOperator(address _operator) external onlyOwner {
        require(_operator != address(0), "Null address provided");
        _setupRole(OPERATOR_ROLE, _operator);
    }

    ///@notice Removes operator role
    ///@param _operator Address that will be removed from the role
    function removeOperator(address _operator) external onlyOwner {
        require(_operator != address(0), "Null address provided");
        revokeRole(OPERATOR_ROLE, _operator);
    }

    ///@notice Checks operator role
    ///@param _user Address to be checked
    ///@return True for the operator
    function isOperator(address _user) public view returns (bool) {
        return hasRole(OPERATOR_ROLE, _user);
    }

    /*****
     * PROCESS THE SIGNATURE
     *****/

    ///@notice checks the signature
    ///@param userFrom - user creator of the signature
    ///@param userTo - user receiver of the signature
    ///@param signature - bytes with the signed message
    function processSignature(
        address userFrom,
        address userTo,
        bytes memory signature
    ) external operatorOnly {
        if (hasSignature(userTo)) {
            return;
        }
        bytes32 message = formMessage(userFrom, userTo);
        require(
            userFrom == recoverAddress(message, signature),
            "Invalid signature provided"
        );
        signatures[userTo] = userFrom;
    }

    ///@notice Returns simple message - hashed concatenation of 2 addresses
    ///@param from - address from
    ///@param to - address to
    ///@return message in a form of hash
    function formMessage(address from, address to)
        public
        pure
        returns (bytes32)
    {
        bytes32 message = keccak256(abi.encodePacked(from, to));
        return message;
    }

    function hasSignature(address sender) public view returns (bool) {
        return signatures[sender] != address(0);
    }

    /*****
     * INTERNAL ECDSA SIGNATURE HELPERS
     *****/
    function stringToBytes32(string memory source)
        public
        pure
        returns (bytes32 result)
    {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }

    function hashMessage(string message) public pure returns (bytes32) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, stringToBytes32(message)));
    }

    function getSigner(
        string message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        require(
            uint256(s) <=
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid signature 's' value"
        );
        require(v == 27 || v == 28, "invalid signature 'v' value");
        address signer = ecrecover(
            hashMessage(stringToBytes32(message)),
            v,
            r,
            s
        );
        require(signer != address(0), "invalid signature");

        return signer;
    }

    function recoverAddress(bytes32 message, bytes memory signature)
        public
        pure
        returns (address)
    {
        if (signature.length != 65) {
            revert("invalid signature length");
        }
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return getSigner(message, v, r, s);
    }
}
