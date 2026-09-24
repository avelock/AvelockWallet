// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

// ============================================================
// Avelock Wallet — Vault factory
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {AvelockWallet} from "./AvelockWallet.sol";
import {AvelockSecurityExtension} from "./extensions/AvelockSecurityExtension.sol";

/// @title AvelockVaultFactory
/// @notice Creates each user's Vault as two EIP-1167 minimal proxies of
///         immutable implementations — ~10x cheaper than deploying the full
///         code per user. Both clones are created and bound in one
///         transaction, so a Vault never exists without its security module.
/// @dev No owner, no admin, no upgrade: the implementations are created here
///      and can only be initialized by this factory. Deploy it through the
///      deterministic CREATE2 deployer so its address is the same on every
///      chain and anyone can deploy it; the address itself proves the code.
contract AvelockVaultFactory {
    address public immutable walletImplementation;
    address public immutable extensionImplementation;

    /// @notice The Vault wallet of an owner, if created.
    mapping(address => address) public vaultOf;

    event VaultCreated(address indexed owner, address wallet, address extension);

    error VaultExists();

    constructor() {
        walletImplementation = address(new AvelockWallet());
        extensionImplementation = address(new AvelockSecurityExtension());
    }

    /// @notice Creates the caller's Vault with the given initial policy. The
    ///         caller is always the owner: nobody can create (and so occupy)
    ///         a Vault for someone else with a weaker policy.
    function createVault(
        uint256 withdrawalDelay,
        uint256 addressDelay,
        uint256 confirmationWindow,
        uint256 policyDelay,
        uint256 minWithdrawalDelay,
        uint256 minAddressDelay
    ) external returns (address wallet, address extension) {
        if (vaultOf[msg.sender] != address(0)) revert VaultExists();
        bytes32 salt = bytes32(uint256(uint160(msg.sender)));
        wallet = Clones.cloneDeterministic(walletImplementation, salt);
        extension = Clones.cloneDeterministic(extensionImplementation, salt);
        AvelockSecurityExtension(extension).initialize(
            wallet, withdrawalDelay, addressDelay, confirmationWindow, policyDelay,
            minWithdrawalDelay, minAddressDelay
        );
        AvelockWallet(payable(wallet)).initialize(msg.sender, extension);
        vaultOf[msg.sender] = wallet;
        emit VaultCreated(msg.sender, wallet, extension);
    }

    /// @notice Where an owner's Vault wallet is (or will be) created.
    function predictVault(address owner) external view returns (address wallet, address extension) {
        bytes32 salt = bytes32(uint256(uint160(owner)));
        wallet = Clones.predictDeterministicAddress(walletImplementation, salt);
        extension = Clones.predictDeterministicAddress(extensionImplementation, salt);
    }
}
