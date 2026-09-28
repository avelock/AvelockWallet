// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

contract PolicyHandler {
    AvelockWallet public wallet;
    AvelockSecurityExtension public extension;
    constructor() {
        (address w, address e) = new AvelockVaultFactory().createVault(1 days, 7 days, 1 days, 7 days, 1 days, 1 days);
        wallet = AvelockWallet(payable(w));
        extension = AvelockSecurityExtension(e);
    }
    function propose(uint256 value) external {
        extension.setWithdrawalDelay(1 days + value % (89 days + 1));
    }
    function cancel() external {
        (, , bool exists) = extension.pendingParamChanges(AvelockSecurityExtension.Param.WithdrawalDelay);
        if (exists) extension.cancelParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
    }
}
contract VaultPolicyProperties is StdInvariant, Test {
    PolicyHandler handler;
    function setUp() public {
        handler = new PolicyHandler();
        targetContract(address(handler));
    }
    function invariantQueuedChangesCannotChangeActivePolicy() public view {
        assertEq(handler.extension().withdrawalDelay(), 1 days);
        assertEq(handler.wallet().owner(), address(handler));
        assertEq(handler.wallet().securityExtension(), address(handler.extension()));
        assertTrue(handler.wallet().extensions(address(handler.extension())));
        assertEq(handler.extension().wallet(), address(handler.wallet()));
    }
    function testFuzzPolicyChangesWaitCurrentDelay(uint256 proposed) public {
        uint256 value = bound(proposed, 1 days + 1, 90 days);
        AvelockSecurityExtension ext = handler.extension();
        vm.prank(address(handler));
        ext.setWithdrawalDelay(value);
        (uint256 queued, uint256 effectiveAt, bool exists) =
            ext.pendingParamChanges(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertTrue(exists);
        assertEq(queued, value);
        assertEq(effectiveAt, block.timestamp + 7 days);
        assertEq(ext.withdrawalDelay(), 1 days);
        vm.warp(effectiveAt);
        vm.prank(address(handler));
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertEq(ext.withdrawalDelay(), value);
    }
    function testFuzzOutOfRangePolicyIsRejected(uint256 proposed) public {
        uint256 value = bound(proposed, 90 days + 1, type(uint256).max);
        AvelockSecurityExtension ext = handler.extension();
        vm.prank(address(handler));
        vm.expectRevert(AvelockSecurityExtension.InvalidParameter.selector);
        ext.setPolicyDelay(value);
    }
}
