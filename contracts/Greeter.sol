//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract DCertify {
    struct VerifiedDocument {
        string document;
        address owner;
        string signature;
    }
    struct image {
        string name;
    }

    mapping(address => VerifiedDocument[]) documents;
    mapping(address => image) mfa;

    //get image name
    function getImageName(address _address)
        public
        view
        returns (string memory)
    {
        return mfa[_address].name;
    }

    function setImageName(address _address, string memory _name) public {
        mfa[_address].name = _name;
    }

    function addDocument(
        string memory _document,
        address _owner,
        string memory _signature
    ) public {
        documents[msg.sender].push(
            VerifiedDocument({
                document: _document,
                owner: _owner,
                signature: _signature
            })
        );
    }

    //get the number of documents
    function getNumberOfDocuments(address _owner)
        public
        view
        returns (uint256)
    {
        return documents[_owner].length;
    }

    //get the number of documents
    function getDocumentByIndex(address _owner, uint256 _index)
        public
        view
        returns (string memory)
    {
        return documents[_owner][_index].document;
    }

    // get all certificates
    function getAllCertificates()
        public
        view
        returns (VerifiedDocument[] memory)
    {
        return documents[msg.sender];
    }

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

    function hashMessage(string memory message) public pure returns (bytes32) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, message));
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }
        function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            uint8,
            bytes32,
            bytes32
        )
    {
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
}
