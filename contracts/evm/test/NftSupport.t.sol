// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Test} from "forge-std/Test.sol";
import {AvelockWallet} from "../src/AvelockWallet.sol";
import {AvelockVaultFactory} from "../src/AvelockVaultFactory.sol";
import {AvelockSecurityExtension} from "../src/extensions/AvelockSecurityExtension.sol";
import {MockERC721} from "./mocks/MockERC721.sol";
import {MockERC1155} from "./mocks/MockERC1155.sol";

/// A contract with no ERC-721/1155 receiver hooks.
contract NoReceiver {}

/// An ERC-721 whose transfer returns without moving anything (A15-9).
contract SilentERC721 {
    function ownerOf(uint256) external view returns (address) { return msg.sender; }
    function safeTransferFrom(address, address, uint256) external {}
}

/// An ERC-1155 whose transfer returns without moving anything (A15-9).
contract SilentERC1155 {
    function balanceOf(address, uint256) external pure returns (uint256) { return 5; }
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external {}
}

contract NftSupportTest is Test {
    address owner = makeAddr("owner");
    address recipient = makeAddr("recipient");
    AvelockWallet wallet;
    AvelockSecurityExtension ext;
    MockERC721 nft721;
    MockERC1155 nft1155;

    function setUp() public {
        // Clone path: the Vault is created by the factory.
        AvelockVaultFactory factory = new AvelockVaultFactory();
        vm.prank(owner);
        (address w, address e) = factory.createVault(1 days, 1 days, 1 days, 1 days, 1 days, 1 days);
        wallet = AvelockWallet(payable(w));
        ext = AvelockSecurityExtension(e);
        nft721 = new MockERC721();
        nft1155 = new MockERC1155();
    }

    function _allow(address to) internal {
        vm.prank(owner);
        ext.addAllowedAddress(to);
        vm.warp(block.timestamp + 1 days + 1);
    }

    function testReceivesErc721ViaSafeTransfer() public {
        nft721.mint(address(this), 1);
        nft721.safeTransferFrom(address(this), address(wallet), 1);
        assertEq(nft721.ownerOf(1), address(wallet));
    }

    function testReceivesErc1155SingleAndBatch() public {
        address sender = makeAddr("sender");
        nft1155.mint(sender, 7, 10);
        nft1155.mint(sender, 8, 5);
        vm.startPrank(sender);
        nft1155.safeTransferFrom(sender, address(wallet), 7, 4, "");
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 7; ids[1] = 8; amounts[0] = 6; amounts[1] = 5;
        nft1155.safeBatchTransferFrom(sender, address(wallet), ids, amounts, "");
        vm.stopPrank();
        assertEq(nft1155.balanceOf(address(wallet), 7), 10);
        assertEq(nft1155.balanceOf(address(wallet), 8), 5);
    }

    function testErc721WithdrawalWaitsForTimelockThenTransfers() public {
        nft721.mint(address(wallet), 42);
        _allow(recipient);
        vm.prank(owner);
        uint256 id = ext.requestNFTWithdrawal(recipient, address(nft721), 42, 1, false);

        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.RequestNotReady.selector);
        ext.confirmWithdrawal(id);

        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        ext.confirmWithdrawal(id);
        assertEq(nft721.ownerOf(42), recipient);
    }

    function testErc1155PartialWithdrawal() public {
        nft1155.mint(address(wallet), 3, 10);
        _allow(recipient);
        vm.prank(owner);
        uint256 id = ext.requestNFTWithdrawal(recipient, address(nft1155), 3, 4, true);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        ext.confirmWithdrawal(id);
        assertEq(nft1155.balanceOf(recipient, 3), 4);
        assertEq(nft1155.balanceOf(address(wallet), 3), 6);
    }

    function testRejectsMalformedNftRequests() public {
        _allow(recipient);
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.InvalidAsset.selector);
        ext.requestNFTWithdrawal(recipient, address(nft721), 1, 2, false); // ERC-721 amount must be 1
        vm.expectRevert(AvelockSecurityExtension.InvalidAsset.selector);
        ext.requestNFTWithdrawal(recipient, address(0), 1, 1, false);
        vm.expectRevert(AvelockSecurityExtension.InvalidAsset.selector);
        ext.requestNFTWithdrawal(recipient, makeAddr("eoa-not-a-token"), 1, 1, false);
        vm.stopPrank();
    }

    function testNftToNonAllowlistedDestinationIsRejected() public {
        nft721.mint(address(wallet), 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.DestinationNotAllowed.selector);
        ext.requestNFTWithdrawal(recipient, address(nft721), 1, 1, false);
    }

    function testRevertingSafeTransferRollsBackAndStaysRetriable() public {
        NoReceiver bad = new NoReceiver();
        nft721.mint(address(wallet), 9);
        _allow(address(bad));
        vm.prank(owner);
        uint256 id = ext.requestNFTWithdrawal(address(bad), address(nft721), 9, 1, false);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert();
        ext.confirmWithdrawal(id);
        assertEq(nft721.ownerOf(9), address(wallet));
        (, , , , , bool executed, ) = ext.requests(id);
        assertFalse(executed); // the whole tx reverted, including executed = true
    }

    function testRevokedDestinationBlocksPendingNftWithdrawal() public {
        nft721.mint(address(wallet), 5);
        _allow(recipient);
        vm.prank(owner);
        uint256 id = ext.requestNFTWithdrawal(recipient, address(nft721), 5, 1, false);
        vm.prank(owner);
        ext.removeAllowedAddress(recipient);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(owner);
        vm.expectRevert(AvelockSecurityExtension.DestinationNotAllowed.selector);
        ext.confirmWithdrawal(id);
        assertEq(nft721.ownerOf(5), address(wallet));
    }

    /// A15-9: a transfer that returns without moving the NFT is not "done".
    function testSilentNftTransfersRevertAndStayRetriable() public {
        SilentERC721 a = new SilentERC721();
        SilentERC1155 b = new SilentERC1155();
        _allow(recipient);
        vm.startPrank(owner);
        uint256 id721 = ext.requestNFTWithdrawal(recipient, address(a), 1, 1, false);
        uint256 id1155 = ext.requestNFTWithdrawal(recipient, address(b), 1, 2, true);
        vm.stopPrank();
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(owner);
        vm.expectRevert(AvelockSecurityExtension.NftTransferFailed.selector);
        ext.confirmWithdrawal(id721);
        vm.expectRevert(AvelockSecurityExtension.NftTransferFailed.selector);
        ext.confirmWithdrawal(id1155);
        vm.stopPrank();
        (,,,,, bool executed,) = ext.requests(id721);
        assertFalse(executed);
    }
}
