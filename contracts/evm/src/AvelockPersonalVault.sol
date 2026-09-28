// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {AvelockWallet} from "./AvelockWallet.sol";
import {AvelockSecurityExtension} from "./extensions/AvelockSecurityExtension.sol";

/// @notice An owner-created, recoverable deployment receipt. Creates a protected
/// wallet atomically; its address is recoverable from the owner's CREATE nonce.
/// @dev The caller picks the initial policy at creation time — e.g. a Deep
///      Vault meant to hold funds for years can start with a stricter
///      config (longer address delay, higher minimums) instead of always
///      starting at one fixed default and having to weaken/strengthen its
///      way there afterward.
contract AvelockPersonalVault {
    address public owner;
    AvelockWallet public wallet;
    AvelockSecurityExtension public extension;

    constructor(
        uint256 withdrawalDelay,
        uint256 addressDelay,
        uint256 confirmationWindow,
        uint256 policyDelay,
        uint256 minWithdrawalDelay,
        uint256 minAddressDelay
    ) {
        owner = msg.sender;
        // Full deployment (used where the clone factory is unavailable, e.g.
        // TRON): this receipt creates and binds both contracts atomically.
        wallet = new AvelockWallet();
        extension = new AvelockSecurityExtension();
        extension.initialize(
            address(wallet), withdrawalDelay, addressDelay, confirmationWindow, policyDelay,
            minWithdrawalDelay, minAddressDelay
        );
        wallet.initialize(msg.sender, address(extension));
    }
}
