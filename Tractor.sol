// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA, EIP712} from "./node_modules/@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title Tractor
/// @notice Holds nonce and helpers for creating, validating, and destroying Blueprints
abstract contract Tractor is EIP712 {
    /* Structs */

    // Blueprint stores blueprint related values.
    struct Blueprint {
        address publisher;
        bytes data;
        uint256 maxNonce;
        uint256 startTime;
        uint256 endTime;
    }

    // SignedBlueprint stores blueprint, hash, and signature, which enables verification.
    struct SignedBlueprint {
        Blueprint blueprint;
        bytes32 blueprintHash;
        bytes signature;
    }

    //Blueprint type enum that defines how to handle data payload.
    // enum BlueprintDataType {} // Implementation Specific

    // Mapping of signature to nonce.
    mapping(bytes32 => uint256) private nonces;

    /* Events */

    /// @notice New blueprint published
    /// @param blueprint Blueprint object
    event PublishedBlueprint(Blueprint blueprint);

    /// @notice Blueprint destroyed
    /// @param blueprintHash Blueprint Hash
    event DestroyedBlueprint(bytes32 blueprintHash);

    /// @notice Action has been taken based on blueprint data
    /// @param operator The operator address
    /// @param blueprintHash Blueprint Hash
    event UsedBlueprint(address indexed operator, bytes32 blueprintHash);

    /* Modifiers */

    /// @notice Verifies that the listed publisher generated the signature for this exact structure.
    /// @param signedBlueprint Blueprint object
    modifier verifySignature(SignedBlueprint calldata signedBlueprint) {
        require(getBlueprintHash(signedBlueprint.blueprint) == signedBlueprint.blueprintHash, "Tractor: invalid hash");
        address signer = ECDSA.recover(signedBlueprint.blueprintHash, signedBlueprint.signature);
        require(signer == signedBlueprint.blueprint.publisher, "Tractor: invalid signature");
        _;
    }

    /// @notice Check that use of the Blueprint is valid, based on metadata. Increment nonce after use.
    /// @param signedBlueprint Blueprint object
    modifier checkMetadataIncrementNonce(SignedBlueprint calldata signedBlueprint) {
        require(
            signedBlueprint.blueprint.startTime < block.timestamp && block.timestamp < signedBlueprint.blueprint.endTime,
            "Tractor: blueprint is not active"
        );
        require(nonces[signedBlueprint.blueprintHash] < signedBlueprint.blueprint.maxNonce, "Tractor: maxNonce reached");
        _;
        nonces[signedBlueprint.blueprintHash]++;
        emit UsedBlueprint(msg.sender, signedBlueprint.blueprintHash);
    }

    /// @notice Perform operation based on blueprint
    /// @param signedBlueprint Blueprint object
    modifier publisherOnly(SignedBlueprint calldata signedBlueprint) {
        require(msg.sender == signedBlueprint.blueprint.publisher, "Tractor: invalid sender");
        _;
    }

    /* Functions */

    /// @notice constructor
    /// @dev see https://docs.openzeppelin.com/contracts/4.x/api/utils#EIP712-constructor-string-string-
    /// @param implName Name of the application using Tractor
    /// @param implVersion Version of the application using Tractor
    constructor(string memory implName, string memory implVersion) EIP712(implName, implVersion) {}

    /// @notice Publish new blueprint
    /// @param signedBlueprint Blueprint object
    function publishBlueprint(SignedBlueprint calldata signedBlueprint) external verifySignature(signedBlueprint) {
        emit PublishedBlueprint(signedBlueprint.blueprint);
    }

    /// @notice Destroy existing blueprint
    /// @param signedBlueprint Blueprint object
    function destroyBlueprint(SignedBlueprint calldata signedBlueprint)
        external
        verifySignature(signedBlueprint)
        publisherOnly(signedBlueprint)
    {
        nonces[signedBlueprint.blueprintHash] = type(uint256).max;
        emit DestroyedBlueprint(signedBlueprint.blueprintHash);
    }

    /// @notice Encode Blueprint data field with type and data
    /// @param dataType bytes1 representing enum value of data type
    /// @param data encoded data of arbitrary structure
    function encodeDataField(bytes1 dataType, bytes calldata data) public pure returns (bytes memory) {
        return abi.encode(bytes1(dataType), data);
    }

    /// @notice Decode blueprint data field into type and data
    /// @param data full data bytes from Blueprint object
    function decodeDataField(bytes calldata data) public pure returns (bytes1, bytes calldata) {
        return (data[1], data[1:]);
    }

    /// @notice calculates blueprint hash
    /// @param blueprint Blueprint object
    /// @return bytes32 calculated blueprint hash
    function getBlueprintHash(Blueprint calldata blueprint) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(blueprint)));
    }
}
