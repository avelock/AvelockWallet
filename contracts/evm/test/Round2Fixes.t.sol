// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

/// Fixes from MEGA_AUDIT/round2/evm.md.
contract Round2FixesTest is Test {
    address owner = makeAddr("owner");
    address guard = makeAddr("guard");
    address thief = makeAddr("thief");
    AvelockWallet wallet;
    AvelockSecurityExtension ext;

    function setUp() public {
        AvelockVaultFactory factory = new AvelockVaultFactory();
        vm.prank(owner);
        // Withdrawal 1 d, address 7 d, window 3 d, policy 1 d, floors 1 d / 1 d: the audit's PoC policy.
        (address w, address e) = factory.createVault(1 days, 7 days, 3 days, 1 days, 1 days, 1 days);
        wallet = AvelockWallet(payable(w));
        ext = AvelockSecurityExtension(e);
        vm.deal(address(wallet), 10 ether);
    }

    /// R2-M01: lowering the address delay waits at least the delay in force.
    function testLoweringTheAddressDelayWaitsTheOldDelay() public {
        vm.prank(owner);
        ext.setAddressDelay(1 days);
        (, uint256 effectiveAt,) = ext.pendingParamChanges(AvelockSecurityExtension.Param.AddressDelay);
        assertEq(effectiveAt, block.timestamp + 7 days);
        // Raising it still waits the ordinary change wait.
        vm.prank(owner);
        ext.setAddressDelay(9 days);
        (, effectiveAt,) = ext.pendingParamChanges(AvelockSecurityExtension.Param.AddressDelay);
        assertEq(effectiveAt, block.timestamp + 1 days);
    }

    /// R2-L01: a matured change expires if not applied in time.
    function testAMaturedChangeExpires() public {
        vm.prank(owner);
        ext.setWithdrawalDelay(2 days);
        vm.warp(block.timestamp + 1 days + ext.APPLY_WINDOW() + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.ChangeExpired.selector);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
    }

    /// R2-L04: the vault and its module are refused as destinations.
    function testVaultAndModuleAreNotDestinations() public {
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.InvalidParameter.selector);
        ext.addAllowedAddress(address(wallet));
        vm.expectRevert(AvelockSecurityExtension.InvalidParameter.selector);
        ext.addAllowedAddress(address(ext));
        vm.stopPrank();
    }

    /// R2-M02, pinned on purpose: a guard holds a phrase thief for a bounded
    /// time only (changeWait + lockDelay), it cannot stop its own removal.
    function testAGuardCannotStopItsOwnRemoval() public {
        vm.prank(owner);
        ext.addGuard(guard);
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(owner); // the phrase thief signs as the owner
        ext.removeGuard(guard);
        vm.prank(guard);
        ext.lock();
        vm.warp(block.timestamp + ext.changeWait() + ext.lockDelay());
        vm.prank(owner);
        ext.finalizeGuardRemoval(guard);
        assertFalse(ext.isGuard(guard));
    }
}
