// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import {IExtension} from "./interfaces/IExtension.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title AvelockWallet
/// @notice Fail-closed vault. Only its permanently installed security module can spend.
/// @dev Install the security module before depositing. No owner execution or upgrade path.
contract AvelockWallet is IERC721Receiver, IERC1155Receiver {
    function protocolVersion() external pure returns (uint256) {
        return 2;
    }

    address public immutable owner;
    address public securityExtension;
    address private immutable initializer;
    uint256 public nonce;

    mapping(address => bool) public extensions;

    event Sent(address indexed to, uint256 value, bytes data);
    event Received(address indexed from, uint256 value);
    event ExtensionAdded(address indexed extension);
    event ExtensionRemoved(address indexed extension);

    error VaultOnly();
    error AlreadyInitialized();
    error InvalidExtension();
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
        initializer = msg.sender;
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

    /// @notice Legacy entry points deliberately fail closed, including old signed messages.
    function execute(address, uint256, bytes calldata, uint256, bytes calldata) external pure returns (bytes memory) {
        revert VaultOnly();
    }

    function executeAsOwner(address, uint256, bytes calldata) external pure returns (bytes memory) {
        revert VaultOnly();
    }

    /// @notice Only the permanently installed module may move assets.
    function executeFromExtension(address to, uint256 value, bytes calldata data)
        external
        onlyExtension
        returns (bytes memory)
    {
        return _call(to, value, data);
    }

    /// @notice One-time bootstrap. Prefer the factory's atomic deployment and installation.
    function addExtension(address extension) external {
        if (msg.sender != owner && msg.sender != initializer) revert NotOwner();
        if (securityExtension != address(0)) revert AlreadyInitialized();
        if (extension.code.length == 0 || IExtension(extension).wallet() != address(this)) revert InvalidExtension();
        securityExtension = extension;
        extensions[extension] = true;
        emit ExtensionAdded(extension);
    }

    function removeExtension(address) external pure {
        revert VaultOnly();
    }

    function _call(address to, uint256 value, bytes calldata data) internal returns (bytes memory) {
        emit Sent(to, value, data);
        (bool ok, bytes memory returndata) = to.call{value: value}(data);
        if (!ok) revert CallFailed(returndata);
        return returndata;
    }
}
