// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

/// Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2).
contract GuardAndLockTest is Test {
    address owner = makeAddr("owner");
    address guard = makeAddr("guard");
    address guard2 = makeAddr("guard2");
    address thiefGuard = makeAddr("thiefGuard");
    address exchange = makeAddr("exchange");
    AvelockWallet wallet;
    AvelockSecurityExtension ext;

    function setUp() public {
        AvelockVaultFactory factory = new AvelockVaultFactory();
        vm.prank(owner);
        (address w, address e) = factory.createVault(1 days, 2 days, 1 days, 3 days, 1 days, 1 days);
        wallet = AvelockWallet(payable(w));
        ext = AvelockSecurityExtension(e);
        vm.deal(address(wallet), 10 ether);
        vm.startPrank(owner);
        ext.addAllowedAddress(exchange);
        ext.addGuard(guard);
        vm.stopPrank();
        vm.warp(block.timestamp + 2 days + 1); // guard and exchange active
    }

    function _request(uint256 amount) internal returns (uint256 id) {
        vm.prank(owner);
        id = ext.requestWithdrawal(exchange, address(0), amount);
    }

    // ---- guards ----

    function testLockDelayDefaultsToAWeekOrTheWithdrawalDelay() public view {
        assertEq(ext.lockDelay(), 7 days);
        assertEq(ext.protocolVersion(), 0);
        assertEq(ext.features() & ext.FEATURE_GUARDS_AND_LOCK(), 1);
    }

    function testNewGuardWaitsTheAddressDelay() public {
        vm.prank(owner);
        ext.addGuard(guard2);
        assertFalse(ext.isGuard(guard2));
        uint256 id = _request(1 ether);
        vm.prank(guard2);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.cancelWithdrawal(id);
        vm.warp(block.timestamp + 2 days);
        assertTrue(ext.isGuard(guard2));
    }

    function testAtMostTwoGuardsAndNoDuplicates() public {
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.GuardExists.selector);
        ext.addGuard(guard);
        ext.addGuard(guard2);
        vm.expectRevert(AvelockSecurityExtension.TooManyGuards.selector);
        ext.addGuard(thiefGuard);
        vm.expectRevert(AvelockSecurityExtension.InvalidParameter.selector);
        ext.addGuard(owner);
        vm.stopPrank();
    }

    function testGuardCancelsAWithdrawalButCannotMoveFunds() public {
        uint256 id = _request(1 ether);
        vm.prank(guard);
        ext.cancelWithdrawal(id);
        (,,,,,, bool cancelled) = ext.requests(id);
        assertTrue(cancelled);

        uint256 id2 = _request(1 ether);
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(guard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.confirmWithdrawal(id2);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.requestWithdrawal(exchange, address(0), 1);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.addAllowedAddress(guard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.addGuard(thiefGuard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.setWithdrawalDelay(2 days);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.removeAllowedAddress(exchange);
        vm.stopPrank();
    }

    function testGuardCancelsQueuedSettingsAndPendingDestinations() public {
        vm.startPrank(owner);
        ext.setWithdrawalDelay(5 days);
        ext.addAllowedAddress(thiefGuard);
        vm.stopPrank();
        vm.startPrank(guard);
        ext.cancelParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        ext.cancelPendingAddress(thiefGuard);
        // An active destination is not the guard's to remove.
        vm.expectRevert(AvelockSecurityExtension.NotPending.selector);
        ext.cancelPendingAddress(exchange);
        vm.stopPrank();
        assertEq(ext.allowlistActiveAt(thiefGuard), 0);
    }

    function testGuardRemovalWaitsAndTheGuardCannotStopIt() public {
        vm.prank(owner);
        ext.removeGuard(guard);
        assertTrue(ext.isGuard(guard)); // still active while the removal waits
        vm.prank(guard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.cancelGuardRemoval(guard);
        vm.prank(guard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.removeGuard(guard);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.ChangeNotReady.selector);
        ext.finalizeGuardRemoval(guard);
        vm.warp(block.timestamp + 2 days);
        vm.prank(owner);
        ext.finalizeGuardRemoval(guard);
        assertFalse(ext.isGuard(guard));
    }

    function testGuardDropsAGuardThatIsStillWaiting() public {
        // A stolen owner key adds its own guard: the real guard stops it.
        vm.prank(owner);
        ext.addGuard(thiefGuard);
        vm.prank(guard);
        ext.removeGuard(thiefGuard);
        vm.warp(block.timestamp + 3 days);
        assertFalse(ext.isGuard(thiefGuard));
    }

    // ---- Panic Lock ----

    function testLockVoidsPendingRequestsAndBlocksNewOnes() public {
        uint256 id = _request(1 ether);
        vm.prank(guard);
        ext.lock();
        assertTrue(ext.locked());
        assertTrue(ext.isRequestAnnulled(id));
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.confirmWithdrawal(id);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.requestWithdrawal(exchange, address(0), 1);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.addAllowedAddress(thiefGuard);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.addGuard(guard2);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.setWithdrawalDelay(2 days);
        vm.stopPrank();
    }

    function testRequestFromBeforeALockStaysVoidAfterUnlock() public {
        uint256 id = _request(1 ether);
        vm.prank(owner);
        ext.lock();
        vm.warp(block.timestamp + 7 days);
        vm.prank(owner);
        ext.unlock();
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.RequestAnnulled.selector);
        ext.confirmWithdrawal(id);
        // A new request works as usual.
        uint256 id2 = _request(1 ether);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        ext.confirmWithdrawal(id2);
        assertEq(exchange.balance, 1 ether);
    }

    function testLockCancelsQueuedChangesPendingGuardsAndPendingDestinations() public {
        vm.startPrank(owner);
        ext.setPolicyDelay(1 days);
        ext.addGuard(thiefGuard);
        ext.addAllowedAddress(guard2);
        ext.lock();
        vm.stopPrank();
        (, , bool exists) = ext.pendingParamChanges(AvelockSecurityExtension.Param.PolicyDelay);
        assertFalse(exists);
        vm.warp(block.timestamp + 7 days);
        assertFalse(ext.isGuard(thiefGuard));
        assertFalse(ext.isAddressActive(guard2)); // was still waiting at the lock
        assertTrue(ext.isAddressActive(exchange)); // was already active
        vm.startPrank(owner);
        ext.unlock();
        assertFalse(ext.isAddressActive(guard2));
        // Adding it again starts a fresh wait.
        ext.addAllowedAddress(guard2);
        vm.stopPrank();
        assertFalse(ext.isAddressActive(guard2));
        vm.warp(block.timestamp + 2 days);
        assertTrue(ext.isAddressActive(guard2));
    }

    function testUnlockWaitsTheLockDelayAndOnlyTheOwnerUnlocks() public {
        vm.prank(guard);
        ext.lock();
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.LockNotExpired.selector);
        ext.unlock();
        vm.warp(block.timestamp + 7 days);
        vm.prank(guard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.unlock();
        vm.prank(owner);
        ext.unlock();
        assertFalse(ext.locked());
    }

    function testLockingAgainExtendsTheWait() public {
        vm.prank(owner);
        ext.lock();
        uint256 first = ext.unlockAfter();
        vm.warp(block.timestamp + 3 days);
        vm.prank(guard);
        ext.lock();
        assertEq(ext.unlockAfter(), first + 3 days);
        assertEq(ext.lockEpoch(), 1); // one lock, extended
    }

    function testWhileLockedCancelsStillWorkButGuardRemovalDoesNot() public {
        uint256 id = _request(1 ether);
        vm.startPrank(owner);
        ext.lock();
        ext.cancelWithdrawal(id);
        ext.removeAllowedAddress(exchange);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.removeGuard(guard);
        vm.stopPrank();
        assertTrue(ext.isGuard(guard));
    }

    /// A15-1: a phrase thief queues the guard's removal; the guard locks; the
    /// removal must not complete during the lock, and the lock drops it.
    function testLockDropsAQueuedGuardRemovalAndItCannotFinishWhileLocked() public {
        vm.prank(owner);
        ext.removeGuard(guard);
        vm.prank(guard);
        ext.lock();
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.VaultLocked.selector);
        ext.finalizeGuardRemoval(guard);
        vm.warp(block.timestamp + 7 days);
        vm.startPrank(owner);
        ext.unlock();
        vm.expectRevert(AvelockSecurityExtension.NotPending.selector);
        ext.finalizeGuardRemoval(guard);
        vm.stopPrank();
        assertTrue(ext.isGuard(guard));
    }

    function testLockDelayCannotGoBelowTheWithdrawalFloor() public {
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.BelowImmutableMinimum.selector);
        ext.setLockDelay(12 hours);
        ext.setLockDelay(2 days);
        vm.warp(block.timestamp + 3 days);
        ext.applyParamChange(AvelockSecurityExtension.Param.LockDelay);
        vm.stopPrank();
        assertEq(ext.lockDelay(), 2 days);
    }

    /// Audit A12-3: a lock never lifts sooner than a withdrawal could complete.
    function testRaisingTheWithdrawalDelayRaisesTheLockDelay() public {
        vm.startPrank(owner);
        ext.setWithdrawalDelay(30 days);
        vm.warp(block.timestamp + ext.policyDelay() + 1);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        vm.stopPrank();
        assertEq(ext.withdrawalDelay(), 30 days);
        assertEq(ext.lockDelay(), 30 days);
    }

    function testALockDelayBelowTheCurrentWithdrawalDelayAppliesAsTheWithdrawalDelay() public {
        vm.startPrank(owner);
        ext.setWithdrawalDelay(20 days);
        ext.setLockDelay(ext.minWithdrawalDelay());
        vm.warp(block.timestamp + ext.policyDelay() + 1);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        // The event reports the value actually stored, not the one proposed.
        vm.expectEmit(address(ext));
        emit AvelockSecurityExtension.ParamChangeApplied(AvelockSecurityExtension.Param.LockDelay, 20 days);
        ext.applyParamChange(AvelockSecurityExtension.Param.LockDelay);
        vm.stopPrank();
        assertEq(ext.lockDelay(), 20 days);
    }

    function testStrangersCannotLock() public {
        vm.prank(thiefGuard);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.lock();
    }

    function testAnnulledRequestCanBePrunedAtOnce() public {
        uint256 id = _request(1 ether);
        vm.prank(owner);
        ext.lock();
        vm.prank(owner);
        ext.pruneRequest(id);
        (address to,,,,,,) = ext.requests(id);
        assertEq(to, address(0));
    }
}
