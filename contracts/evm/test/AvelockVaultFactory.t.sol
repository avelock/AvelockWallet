// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test, console} from "forge-std/Test.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockPersonalVault} from "../src/AvelockPersonalVault.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

contract AvelockVaultFactoryTest is Test {
    AvelockVaultFactory factory;
    address owner = makeAddr("owner");
    address recipient = makeAddr("recipient");

    function setUp() public {
        factory = new AvelockVaultFactory();
    }

    function _create(address who) internal returns (AvelockWallet wallet, AvelockSecurityExtension ext) {
        vm.prank(who);
        (address w, address e) = factory.createVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days);
        return (AvelockWallet(payable(w)), AvelockSecurityExtension(e));
    }

    function testCreatesBoundVaultAtPredictedAddresses() public {
        (address pw, address pe) = factory.predictVault(owner);
        (AvelockWallet wallet, AvelockSecurityExtension ext) = _create(owner);
        assertEq(address(wallet), pw);
        assertEq(address(ext), pe);
        assertEq(factory.vaultOf(owner), pw);
        assertEq(wallet.owner(), owner);
        assertEq(wallet.securityExtension(), address(ext));
        assertTrue(wallet.extensions(address(ext)));
        assertEq(ext.wallet(), address(wallet));
        assertEq(ext.withdrawalDelay(), 1 days);
        assertEq(ext.minAddressDelay(), 1 days);
    }

    function testOneVaultPerOwnerAndOnlyForTheCaller() public {
        _create(owner);
        vm.prank(owner);
        vm.expectRevert(AvelockVaultFactory.VaultExists.selector);
        factory.createVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days);
        // Someone else's call creates *their* vault, never one owned by `owner`.
        address other = makeAddr("other");
        (AvelockWallet w2,) = _create(other);
        assertEq(w2.owner(), other);
    }

    function testNobodyCanInitializeClonesOrImplementationsAgain() public {
        (AvelockWallet wallet, AvelockSecurityExtension ext) = _create(owner);
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        vm.expectRevert(AvelockWallet.VaultOnly.selector);
        wallet.initialize(attacker, attacker);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.initialize(attacker, 1, 1, 1, 1, 1, 1);
        AvelockWallet impl = AvelockWallet(payable(factory.walletImplementation()));
        vm.expectRevert(AvelockWallet.VaultOnly.selector);
        impl.initialize(attacker, attacker);
        AvelockSecurityExtension extImpl = AvelockSecurityExtension(factory.extensionImplementation());
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        extImpl.initialize(attacker, 1 days, 1 days, 1 days, 1 days, 1 days, 1 days);
        vm.stopPrank();
        // Even the factory cannot re-initialize an existing clone.
        vm.prank(address(factory));
        vm.expectRevert(AvelockWallet.AlreadyInitialized.selector);
        wallet.initialize(attacker, attacker);
        vm.prank(address(factory));
        vm.expectRevert(AvelockSecurityExtension.AlreadyInitialized.selector);
        ext.initialize(attacker, 1 days, 1 days, 1 days, 1 days, 1 days, 1 days);
        assertEq(wallet.owner(), owner);
    }

    function testRejectsAWeakPolicyAtCreation() public {
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.BelowImmutableMinimum.selector);
        factory.createVault(1 hours, 7 days, 1 days, 7 days, 1 days, 1 days);
        assertEq(factory.vaultOf(owner), address(0));
    }

    function testCloneHoldsEthAndWithdrawsOnlyAfterTheDelay() public {
        (AvelockWallet wallet, AvelockSecurityExtension ext) = _create(owner);
        vm.deal(address(this), 5 ether);
        (bool ok,) = address(wallet).call{value: 2 ether}("");
        assertTrue(ok);
        vm.startPrank(owner);
        ext.addAllowedAddress(recipient);
        vm.warp(block.timestamp + 7 days);
        uint256 id = ext.requestWithdrawal(recipient, address(0), 1 ether);
        vm.expectRevert(AvelockSecurityExtension.RequestNotReady.selector);
        ext.confirmWithdrawal(id);
        vm.warp(block.timestamp + 1 days);
        ext.confirmWithdrawal(id);
        vm.stopPrank();
        assertEq(recipient.balance, 1 ether);
        assertEq(address(wallet).balance, 1 ether);
        // The wallet has no owner execution path.
        vm.prank(owner);
        vm.expectRevert(AvelockWallet.VaultOnly.selector);
        wallet.executeAsOwner(recipient, 1 ether, "");
    }

    /// A full AvelockPersonalVault deployment costs ~2.76M gas (eth_estimateGas on Sepolia).
    function testCloneCreationIsCheap() public {
        vm.prank(owner);
        uint256 g = gasleft();
        factory.createVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days);
        uint256 cloneGas = g - gasleft();
        console.log("clone vault gas", cloneGas);
        assertLt(cloneGas, 450_000);
    }

    // Audit A3-3: plain ETH via .transfer()/.send() (2300 gas) reaches a clone vault.
    function testCloneAcceptsTransferWithGasStipend() public {
        (AvelockWallet wallet, AvelockSecurityExtension ext) = _create(owner);
        Payer payer = new Payer();
        vm.deal(address(payer), 3 ether);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AvelockWallet.Received(address(payer), 1 ether);
        payer.viaTransfer(payable(address(wallet)), 1 ether);
        assertTrue(payer.viaSend(payable(address(wallet)), 1 ether));
        assertEq(address(wallet).balance, 2 ether);
        // Calls with data still reach the implementation.
        assertEq(wallet.owner(), owner);
        assertEq(wallet.securityExtension(), address(ext));
        // And the ETH leaves only through the delayed path.
        vm.prank(owner);
        ext.addAllowedAddress(recipient);
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(owner);
        uint256 id = ext.requestWithdrawal(recipient, address(0), 0.5 ether);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        ext.confirmWithdrawal(id);
        assertEq(recipient.balance, 0.5 ether);
    }
}

contract Payer {
    function viaTransfer(address payable to, uint256 v) external { to.transfer(v); }
    function viaSend(address payable to, uint256 v) external returns (bool) { return to.send(v); }
}
