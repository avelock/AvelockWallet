// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";

/// Standard ERC-20: transfer returns true, reverts on insufficient balance.
contract MockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// USDT-style: transfer returns nothing.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}

/// Tether on TRON: moves the tokens but returns false (audit H-5).
contract TronUsdtToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return false;
    }
}

/// Returns false and moves less than asked.
contract ShortFalseToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount / 2;
        balanceOf[to] += amount / 2;
        return false;
    }
}

/// Signals failure by returning false instead of reverting.
contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) { return false; }
}

contract Erc20SupportTest is Test {
    address owner = makeAddr("owner");
    address recipient = makeAddr("recipient");
    AvelockWallet wallet;
    AvelockSecurityExtension ext;

    function setUp() public {
        AvelockVaultFactory factory = new AvelockVaultFactory();
        vm.prank(owner);
        (address w, address e) = factory.createVault(1 days, 1 days, 1 days, 1 days, 1 days, 1 days);
        wallet = AvelockWallet(payable(w));
        ext = AvelockSecurityExtension(e);
        vm.prank(owner);
        ext.addAllowedAddress(recipient);
        vm.warp(block.timestamp + 1 days + 1);
    }

    function _request(address token, uint256 amount) internal returns (uint256 id) {
        vm.prank(owner);
        id = ext.requestWithdrawal(recipient, token, amount);
    }

    function _confirm(uint256 id) internal {
        vm.prank(owner);
        ext.confirmWithdrawal(id);
    }

    function testErc20WithdrawalWaitsForTimelockThenTransfersExactAmount() public {
        MockToken token = new MockToken();
        token.mint(address(wallet), 100e6);
        uint256 id = _request(address(token), 40e6);

        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.RequestNotReady.selector);
        ext.confirmWithdrawal(id);

        vm.warp(block.timestamp + 1 days + 1);
        _confirm(id);
        assertEq(token.balanceOf(recipient), 40e6);
        assertEq(token.balanceOf(address(wallet)), 60e6);
    }

    function testTokenWithoutReturnValueIsSupported() public {
        NoReturnToken token = new NoReturnToken();
        token.mint(address(wallet), 5e6);
        uint256 id = _request(address(token), 5e6);
        vm.warp(block.timestamp + 1 days + 1);
        _confirm(id);
        assertEq(token.balanceOf(recipient), 5e6);
    }

    function testTronUsdtReturningFalseOnSuccessIsSupported() public {
        TronUsdtToken token = new TronUsdtToken();
        token.mint(address(wallet), 7e6);
        uint256 id = _request(address(token), 7e6);
        vm.warp(block.timestamp + 1 days + 1);
        _confirm(id);
        assertEq(token.balanceOf(recipient), 7e6);
        assertEq(token.balanceOf(address(wallet)), 0);
    }

    function testFalseReturnWithWrongBalanceChangeReverts() public {
        ShortFalseToken token = new ShortFalseToken();
        token.mint(address(wallet), 10);
        uint256 id = _request(address(token), 10);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.Erc20TransferFailed.selector);
        ext.confirmWithdrawal(id);
    }

    function testFalseReturningTokenRevertsAndStaysRetriable() public {
        FalseToken token = new FalseToken();
        uint256 id = _request(address(token), 1);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.Erc20TransferFailed.selector);
        ext.confirmWithdrawal(id);
        (, , , , , bool executed, ) = ext.requests(id);
        assertFalse(executed);
    }

    function testInsufficientTokenBalanceRevertsWithoutMarkingExecuted() public {
        MockToken token = new MockToken();
        token.mint(address(wallet), 1e6);
        uint256 id = _request(address(token), 2e6);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert();
        ext.confirmWithdrawal(id);
        (, , , , , bool executed, ) = ext.requests(id);
        assertFalse(executed);
        assertEq(token.balanceOf(address(wallet)), 1e6);
    }

    function testRemovedDestinationBlocksPendingTokenWithdrawal() public {
        MockToken token = new MockToken();
        token.mint(address(wallet), 10e6);
        uint256 id = _request(address(token), 10e6);
        vm.prank(owner);
        ext.removeAllowedAddress(recipient);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.DestinationNotAllowed.selector);
        ext.confirmWithdrawal(id);
        assertEq(token.balanceOf(address(wallet)), 10e6);
    }

    function testTokenAddressMustBeAContract() public {
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.InvalidAsset.selector);
        ext.requestWithdrawal(recipient, makeAddr("not-a-contract"), 1);
    }

    function testOnlyTheOwnerCanRequestTokenWithdrawals() public {
        MockToken token = new MockToken();
        vm.prank(recipient);
        vm.expectRevert(AvelockSecurityExtension.NotOwner.selector);
        ext.requestWithdrawal(recipient, address(token), 1);
    }

    // Audit M-1: re-setting the current value withdraws a queued change.
    function testSettingCurrentValueWithdrawsPendingChange() public {
        vm.prank(owner);
        ext.setWithdrawalDelay(2 days);
        (, , bool queued) = ext.pendingParamChanges(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertTrue(queued);
        vm.prank(owner);
        ext.setWithdrawalDelay(1 days);
        (, , bool still) = ext.pendingParamChanges(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertFalse(still);
        vm.warp(block.timestamp + 2 days);
        vm.prank(owner);
        vm.expectRevert();
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertEq(ext.withdrawalDelay(), 1 days);
    }

    // AVL-EVM-001: the Applied event carries the value that took effect.
    function testParamChangeAppliedEventCarriesTheNewValue() public {
        vm.prank(owner);
        ext.setWithdrawalDelay(2 days);
        vm.warp(block.timestamp + 1 days + 1);
        vm.expectEmit(true, false, false, true, address(ext));
        emit AvelockSecurityExtension.ParamChangeApplied(AvelockSecurityExtension.Param.WithdrawalDelay, 2 days);
        vm.prank(owner);
        ext.applyParamChange(AvelockSecurityExtension.Param.WithdrawalDelay);
        assertEq(ext.withdrawalDelay(), 2 days);
    }
}
