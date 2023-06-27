// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Blueprint, SignedBlueprint} from "./Tractor.sol";

interface ITractor {
    function publishBlueprint(SignedBlueprint memory signedBlueprint) external;
    function destroyBlueprint(SignedBlueprint calldata signedBlueprint) external;
    function domainSeparator() external view returns (bytes32);
    function getBlueprintHash(Blueprint memory blueprint) external view returns (bytes32);
    function isValidSignature(bytes32 blueprintHash, bytes memory) external view returns (bytes4 magicValue);
    function packDataField(bytes1 dataType, bytes memory data) external pure returns (bytes memory);
    function unpackDataField(bytes calldata data) external pure returns (bytes1, bytes calldata);
}
