// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {AvelockPersonalVault} from "../src/AvelockPersonalVault.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

contract AvelockPersonalVaultTest is Test {
    function testDirectDeploymentAlreadyHasTrustedProtection() public {
        address owner = makeAddr("owner");
        vm.prank(owner);
        AvelockWallet wallet = new AvelockPersonalVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days).wallet();
        assertEq(wallet.owner(), owner);
        assertEq(wallet.protocolVersion(), 0);
        assertTrue(wallet.extensions(wallet.securityExtension()));
        vm.prank(owner);
        vm.expectRevert(AvelockWallet.AlreadyInitialized.selector);
        wallet.addExtension(address(1));
    }

    function _vault(address owner) internal returns (AvelockPersonalVault receipt) {
        vm.prank(owner);
        receipt = new AvelockPersonalVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days);
    }

    function testPersonalReceiptAndRecoveryRemainAtomic() public {
        address owner = makeAddr("receipt owner");
        address expected = vm.computeCreateAddress(owner, vm.getNonce(owner));
        AvelockPersonalVault receipt = _vault(owner);
        assertEq(address(receipt), expected);
        assertEq(receipt.wallet().securityExtension(), address(receipt.extension()));
        assertEq(receipt.extension().wallet(), address(receipt.wallet()));
        assertEq(receipt.extension().protocolVersion(), 0);
        assertEq(receipt.extension().withdrawalDelay(), 1 days);
    }

    function testCreationAcceptsAStricterInitialPolicyThanTheDefault() public {
        address owner = makeAddr("deep vault owner");
        vm.prank(owner);
        AvelockPersonalVault receipt =
            new AvelockPersonalVault(3 days, 30 days, 2 days, 14 days, 3 days, 30 days);
        assertEq(receipt.extension().addressDelay(), 30 days);
        assertEq(receipt.extension().minAddressDelay(), 30 days);
        assertEq(receipt.extension().policyDelay(), 14 days);
    }

    function testOwnerCannotReplaceTheOriginalOwnerEvenAfterPolicyDelay() public {
        address owner = makeAddr("owner");
        AvelockPersonalVault receipt = _vault(owner);
        AvelockSecurityExtension ext = receipt.extension();
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.OwnerRotationDisabled.selector);
        ext.proposeOwnerRotation(makeAddr("replacement"));
        vm.warp(block.timestamp + 365 days);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.OwnerRotationDisabled.selector);
        ext.applyOwnerRotation();
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.OwnerRotationDisabled.selector);
        ext.cancelOwnerRotation();
        assertEq(receipt.wallet().owner(), owner);
        vm.prank(owner);
        ext.addAllowedAddress(makeAddr("still controlled"));
    }

    function testModuleCannotChangeImmutableWalletOwner() public {
        address owner = makeAddr("immutable owner");
        AvelockPersonalVault receipt = _vault(owner);
        AvelockWallet wallet = receipt.wallet();
        vm.prank(address(receipt.extension()));
        vm.expectRevert(AvelockWallet.VaultOnly.selector);
        wallet.rotateOwner(address(0));
        assertEq(wallet.owner(), owner);
    }

    function testCancelledRequestPrunesImmediately() public {
        address owner = makeAddr("prune owner cancel");
        address dest = makeAddr("prune dest cancel");
        AvelockPersonalVault receipt = _vault(owner);
        AvelockSecurityExtension ext = receipt.extension();

        vm.prank(owner);
        ext.addAllowedAddress(dest);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(owner);
        uint256 requestId = ext.requestWithdrawal(dest, address(0), 1 ether);

        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.RequestNotReady.selector);
        ext.pruneRequest(requestId);

        vm.prank(owner);
        ext.cancelWithdrawal(requestId);

        vm.prank(owner);
        ext.pruneRequest(requestId);

        (address to, , uint256 amount, , , , ) = ext.requests(requestId);
        assertEq(to, address(0));
        assertEq(amount, 0);
    }

    function testSettledRequestOnlyPrunesAfterRetentionWindow() public {
        address owner = makeAddr("prune owner settled");
        address dest = makeAddr("prune dest settled");
        AvelockPersonalVault receipt = _vault(owner);
        AvelockSecurityExtension ext = receipt.extension();

        vm.prank(owner);
        ext.addAllowedAddress(dest);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(owner);
        uint256 requestId = ext.requestWithdrawal(dest, address(0), 1 ether);
        vm.deal(address(receipt.wallet()), 1 ether);

        (, , , , uint256 expiresAt, , ) = ext.requests(requestId);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        ext.confirmWithdrawal(requestId);

        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.RequestNotReady.selector);
        ext.pruneRequest(requestId);

        vm.warp(expiresAt + 182 days + 1);
        vm.prank(owner);
        ext.pruneRequest(requestId);

        (address to, , uint256 amount, , , , ) = ext.requests(requestId);
        assertEq(to, address(0));
        assertEq(amount, 0);
    }

    /// A14-2: a short policy delay must not lower the withdrawal delay sooner
    /// than a withdrawal under it could complete.
    function testParamChangeWaitsAtLeastTheWithdrawalDelay() public {
        address owner = makeAddr("short policy owner");
        vm.prank(owner);
        AvelockPersonalVault receipt = new AvelockPersonalVault(14 days, 1 days, 1 days, 1 days, 1 days, 1 days);
        AvelockSecurityExtension ext = receipt.extension();
        assertEq(ext.changeWait(), 14 days);
        vm.prank(owner);
        ext.setWithdrawalDelay(1 days);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.ChangeNotReady.selector);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        vm.warp(block.timestamp + 13 days);
        vm.prank(owner);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertEq(ext.withdrawalDelay(), 1 days);
        // With a policy delay longer than the withdrawal delay, the policy delay rules.
        assertEq(ext.changeWait(), 1 days);
    }
}
