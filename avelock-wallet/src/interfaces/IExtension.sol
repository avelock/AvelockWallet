// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Marker interface for AvelockWallet extensions.
/// @dev An extension is any contract the owner has authorized to call
///      `executeFromExtension` on the wallet without an owner signature.
///      Future security modules (timelock, allowlist, duress) implement
///      this as the point where they plug into the wallet core.
interface IExtension {
    function wallet() external view returns (address);
}
