// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

/// @notice Marker interface for AvelockWallet extensions.
/// @dev The extension bound to the wallet at its creation calls
///      `executeFromExtension` without an owner signature. The owner cannot
///      add or replace extensions afterwards (round2 R2-L06).
///      Future security modules (timelock, allowlist, duress) implement
///      this as the point where they plug into the wallet core.
interface IExtension {
    function wallet() external view returns (address);
}
