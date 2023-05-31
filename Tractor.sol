// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA, EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

// NOTE can use uint8 instead of bytes1 for type via enum?

// NOTE eoa use will use calldata args but internal calls will use memory args. duplicate all functions with external
//      and internal modifiers? solidity forces such bad coding practices...

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

/// @title Tractor
/// @notice Holds nonce and helpers for creating, validating, and destroying Blueprints
abstract contract Tractor is EIP712, IERC1271 {
    // Blueprint type enum that defines how to handle data payload.
    // enum BlueprintDataType {} // Implementation Specific

    // Record of hashes this contract has signed.
    mapping(bytes32 => bool) private signedHashes;
    // Mapping of signature to nonce.
    mapping(bytes32 => uint256) private nonces;

    /* Events */

    /// @notice New blueprint published
    /// @param signedBlueprint SignedBlueprint object
    event PublishedBlueprint(SignedBlueprint signedBlueprint);

    /// @notice Blueprint destroyed
    /// @param blueprintHash Blueprint Hash
    event DestroyedBlueprint(bytes32 blueprintHash);

    /// @notice Action has been taken based on blueprint data
    /// @param operator The operator address
    /// @param blueprintHash Blueprint Hash
    event UsedBlueprint(address indexed operator, bytes32 blueprintHash);

    /* Modifiers */

    // NOTE Should this function be defined twice - once with calldata and once with memory args?
    /// @notice Verifies that the listed publisher generated the signature for this exact structure.
    /// @param signedBlueprint Blueprint object
    modifier verifySignature(SignedBlueprint memory signedBlueprint) {
        require(getBlueprintHash(signedBlueprint.blueprint) == signedBlueprint.blueprintHash, "Tractor: invalid hash");
        // NOTE this function is slightly less gas efficient for certain cases. Additionally, it could be optimized
        //      if we expect that many signatures will have been signed by this contract itself.
        require(
            SignatureChecker.isValidSignatureNow(
                signedBlueprint.blueprint.publisher, signedBlueprint.blueprintHash, signedBlueprint.signature
            )
        );
        _;
    }

    /// @notice Check that use of the Blueprint is valid, based on metadata.
    /// @dev Only use when not tracking uses via nonce system, otherwise use verifyUseIncrementBlueprint.
    /// @param signedBlueprint Blueprint object
    modifier useBlueprint(SignedBlueprint calldata signedBlueprint) {
        _verifyMetadata(signedBlueprint);
        _;
        emit UsedBlueprint(msg.sender, signedBlueprint.blueprintHash);
    }

    /// @notice Check that use of the Blueprint is valid, based on metadata. Increment nonce after use.
    /// @param signedBlueprint Blueprint object
    modifier useBlueprintIncrement(SignedBlueprint calldata signedBlueprint) {
        _verifyMetadata(signedBlueprint);
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

    // NOTE Should this function be defined twice - once with calldata and once with memory args?
    /// @notice Publish new blueprint
    /// @param signedBlueprint Blueprint object
    function publishBlueprint(SignedBlueprint memory signedBlueprint) public verifySignature(signedBlueprint) {
        emit PublishedBlueprint(signedBlueprint);
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
    function packDataField(bytes1 dataType, bytes memory data) public pure returns (bytes memory) {
        return abi.encode(bytes1(dataType), data);
    }

    /// @notice Decode blueprint data field into type and data
    /// @param data full data bytes from Blueprint object
    function unpackDataField(bytes calldata data) public pure returns (bytes1, bytes calldata) {
        return (data[1], data[1:]);
    }

    // NOTE Should this function be defined twice - once with calldata and once with memory args?
    /// @notice calculates blueprint hash
    /// @param blueprint Blueprint object
    /// @return bytes32 calculated blueprint hash
    function getBlueprintHash(Blueprint memory blueprint) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(blueprint)));
    }

    /// @notice signs the blueprint by storing hash in map of known hashes.
    /// @dev assumes valid blueprint hash.
    function signBlueprint(bytes32 blueprintHash) internal {
        // NOTE: benefits of using merkle tree here?
        signedHashes[blueprintHash] = true;
    }

    // TODO: need a sanity check on this 1271 implementation.
    function isValidSignature(bytes32 blueprintHash, bytes memory) external view returns (bytes4 magicValue) {
        if (signedHashes[blueprintHash]) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    function _verifyMetadata(SignedBlueprint calldata signedBlueprint) private view {
        require(
            signedBlueprint.blueprint.startTime < block.timestamp && block.timestamp < signedBlueprint.blueprint.endTime,
            "Tractor: blueprint is not active"
        );
        require(nonces[signedBlueprint.blueprintHash] < signedBlueprint.blueprint.maxNonce, "Tractor: maxNonce reached");
    }
}
