// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA, EIP712} from "./node_modules/@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title Tractor
/// @notice Holds nonce and helpers for Blueprints
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
    event executedBlueprint(address indexed operator, bytes32 blueprintHash);

    /* Modifiers */

    /// @notice Verifies that the listed publisher generated the signature for this exact structure.
    /// @param signedBlueprint Blueprint object
    modifier verifySignature(SignedBlueprint calldata signedBlueprint) {
        require(getBlueprintHash(signedBlueprint.blueprint) == signedBlueprint.blueprintHash, "Tractor: invalid hash");
        address signer = ECDSA.recover(signedBlueprint.blueprintHash, signedBlueprint.signature);
        require(signer == signedBlueprint.blueprint.publisher, "Tractor: invalid signature");
        _;
    }

    /// @notice constructor
    /// @dev see https://docs.openzeppelin.com/contracts/4.x/api/utils#EIP712-constructor-string-string-
    /// @param implName Name of the application using Tractor
    /// @param implVersion Version of the application using Tractor
    constructor(string memory implName, string memory implVersion) EIP712(implName, implVersion) {}

    /* Functions */

    /// @notice Publish new blueprint
    /// @param signedBlueprint Blueprint object
    function publishBlueprint(SignedBlueprint calldata signedBlueprint) external verifySignature(signedBlueprint) {
        emit PublishedBlueprint(signedBlueprint.blueprint);
    }

    /// @notice Destroy existing blueprint
    /// @param signedBlueprint Blueprint object
    function destroyBlueprint(SignedBlueprint calldata signedBlueprint) external verifySignature(signedBlueprint) {
        require(msg.sender == signedBlueprint.blueprint.publisher, "Tractor: only publisher can destroy");
        nonces[signedBlueprint.blueprintHash] = type(uint256).max;
        emit DestroyedBlueprint(signedBlueprint.blueprintHash);
    }

    /// @notice Perform operation based on blueprint
    /// @param signedBlueprint Blueprint object
    /// @param callData callData set by tractor operator
    /// @return results arbitrary data returned from execution
    function executeBlueprint(SignedBlueprint calldata signedBlueprint, bytes calldata callData)
        external
        payable
        verifySignature(signedBlueprint)
        returns (bytes[] memory results)
    {
        require(
            signedBlueprint.blueprint.startTime < block.timestamp && block.timestamp < signedBlueprint.blueprint.endTime,
            "Tractor: blueprint is not active"
        );
        require(nonces[signedBlueprint.blueprintHash] < signedBlueprint.blueprint.maxNonce, "Tractor: maxNonce reached");
        nonces[signedBlueprint.blueprintHash]++;

        results = _executeBlueprint(signedBlueprint.blueprint.data[0], signedBlueprint.blueprint.data[1:], callData);

        emit executedBlueprint(msg.sender, signedBlueprint.blueprintHash);
    }

    /// @notice calculates blueprint hash
    /// @param blueprint Blueprint object
    /// @return bytes32 calculated blueprint hash
    function getBlueprintHash(Blueprint calldata blueprint) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(blueprint)));
    }

    /// @notice Decode and execute logic based on the Blueprint data
    /// @dev Should verify sender has authority to execute. Assumes metadata requirements are met
    /// @param dataType uint8 corresponding to a type in BlueprintDataType
    /// @param data blueprint data following type byte. used to execute desired implementation-specific functionality
    /// @param callData operator specified data. used to execute desired implementation-specific functionality
    function _executeBlueprint(bytes1 dataType, bytes calldata data, bytes calldata callData)
        internal
        virtual
        returns (bytes[] memory results); // Implementation Specific
}
