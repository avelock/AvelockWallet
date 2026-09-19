// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title AvelockWallet
/// @notice Minimal smart-contract wallet account, modeled after TON Wallet
///         V5R1: a single owner key controls the account, every outgoing
///         call is authorized either by an owner signature or by an
///         explicitly authorized extension address. There is no generic
///         "call anything" admin path.
/// @dev This is the base wallet layer only. Timelocks, address allowlists,
///      withdrawal delays and the duress-PIN flow are NOT implemented here
///      — they are meant to be added later as an extension contract that
///      the owner authorizes via addExtension/removeExtension.
contract AvelockWallet is IERC721Receiver, IERC1155Receiver {
    using ECDSA for bytes32;

    address public owner;
    uint256 public nonce;

    mapping(address => bool) public extensions;

    event Sent(address indexed to, uint256 value, bytes data);
    event Received(address indexed from, uint256 value);
    event ExtensionAdded(address indexed extension);
    event ExtensionRemoved(address indexed extension);

    error NotOwner();
    error NotExtension();
    error BadNonce();
    error BadSignature();
    error CallFailed(bytes returndata);
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyExtension() {
        if (!extensions[msg.sender]) revert NotExtension();
        _;
    }

    constructor(address _owner) {
        if (_owner == address(0)) revert ZeroAddress();
        owner = _owner;
    }

    /// @notice Accept plain ETH transfers with no restriction — incoming
    ///         funds are never subject to delay.
    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    /// @notice Accept safeTransferFrom of any ERC-721 with no restriction —
    ///         same "incoming is never delayed" rule as receive() (see
    ///         threat-model section 28).
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC721Receiver).interfaceId || interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice Execute an owner-signed operation (offline-signed message,
    ///         analogous to a TON external message). Lets a relayer submit
    ///         the transaction on the owner's behalf without the owner
    ///         needing ETH for gas or a direct on-chain msg.sender call.
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonceUsed,
        bytes calldata signature
    ) external returns (bytes memory) {
        if (nonceUsed != nonce) revert BadNonce();

        bytes32 opHash = _hashOperation(to, value, data, nonceUsed);
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(opHash);
        address signer = ethSignedHash.recover(signature);
        if (signer != owner) revert BadSignature();

        nonce++;
        return _call(to, value, data);
    }

    /// @notice Execute directly as the owner (msg.sender == owner), no
    ///         offline signature required. Simpler UX path when the owner
    ///         is sending the transaction themselves.
    function executeAsOwner(address to, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        return _call(to, value, data);
    }

    /// @notice Execute on behalf of the wallet from an authorized extension,
    ///         without any owner signature. This is the sole point where
    ///         future security modules (timelock/allowlist/duress) attach.
    function executeFromExtension(address to, uint256 value, bytes calldata data)
        external
        onlyExtension
        returns (bytes memory)
    {
        return _call(to, value, data);
    }

    /// @notice Authorize a new extension. Granting an extension is a
    ///         strengthening of what the owner can delegate, so it applies
    ///         immediately — same as any other owner action in this base
    ///         layer. (When a security-policy module is layered on top,
    ///         changes here may become subject to a delay.)
    function addExtension(address extension) external onlyOwner {
        if (extension == address(0)) revert ZeroAddress();
        extensions[extension] = true;
        emit ExtensionAdded(extension);
    }

    /// @notice Revoke a previously authorized extension.
    function removeExtension(address extension) external onlyOwner {
        extensions[extension] = false;
        emit ExtensionRemoved(extension);
    }

    function _call(address to, uint256 value, bytes calldata data) internal returns (bytes memory) {
        emit Sent(to, value, data);
        (bool ok, bytes memory returndata) = to.call{value: value}(data);
        if (!ok) revert CallFailed(returndata);
        return returndata;
    }

    /// @dev Binds the signed hash to this specific wallet, this chain and
    ///      this nonce so a signature cannot be replayed against another
    ///      wallet, another network, or reused after execution.
    function _hashOperation(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonceUsed
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(address(this), block.chainid, to, value, data, nonceUsed)
        );
    }
}
