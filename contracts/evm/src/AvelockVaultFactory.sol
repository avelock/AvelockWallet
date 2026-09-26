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
        wallet = _cloneReceiving(walletImplementation, salt);
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
    /// @dev Minimal proxy that accepts plain ETH itself and delegates every
    ///      other call. EIP-1167 delegates even an empty call, and the cold
    ///      access to the implementation (2600 gas) alone exceeds the 2300 gas
    ///      that `.transfer()` / `.send()` forward, so such payments reverted
    ///      (audit A3-3). The empty-call path emits the wallet's own
    ///      `Received(address indexed from, uint256 value)` itself (~1.4k gas),
    ///      so deposit history and alerts keep working. Runtime (95 bytes):
    ///        36 15 6032 57                        if calldatasize == 0 goto RECV
    ///        363d3d373d3d3d363d73 <impl>          EIP-1167 body, its jump target
    ///        5af43d82803e903d91 6030 57 fd 5b f3     moved by the 5-byte prefix
    ///        5b 34 6000 52 33 7f <topic0>          RECV: mem[0] = value, topic1 = caller
    ///        6020 6000 a2 00                       LOG2(0, 32, topic0, caller); STOP
    function _receivingInitCode(address impl) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"3d605f80600a3d3981f3",
            hex"3615603257363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91603057fd5bf3",
            hex"5b34600052337f", keccak256("Received(address,uint256)"), hex"60206000a200"
        );
    }

    function _cloneReceiving(address impl, bytes32 salt) internal returns (address instance) {
        bytes memory code = _receivingInitCode(impl);
        assembly {
            instance := create2(0, add(code, 0x20), mload(code), salt)
        }
        if (instance == address(0)) revert VaultExists();
    }

    function predictVault(address owner) external view returns (address wallet, address extension) {
        bytes32 salt = bytes32(uint256(uint160(owner)));
        wallet = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, keccak256(_receivingInitCode(walletImplementation))
        )))));
        extension = Clones.predictDeterministicAddress(extensionImplementation, salt);
    }
}
