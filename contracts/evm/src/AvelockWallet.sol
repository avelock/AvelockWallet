// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title AvelockWallet
/// @notice Fail-closed vault. Only its permanently installed security module can spend.
/// @dev No owner execution or upgrade path. Created together with its one
///      security module by a deployer (AvelockVaultFactory for clones,
///      AvelockPersonalVault for a full deployment), which binds both in the
///      same transaction through the one-time initialize().
contract AvelockWallet is IERC721Receiver, IERC1155Receiver {
    function protocolVersion() external pure returns (uint256) {
        return 0;
    }

    /// @dev The only address allowed to initialize. In a clone this is the
    ///      implementation's immutable, i.e. the factory.
    address public immutable deployer;

    /// @dev Set once by initialize(); never changes afterwards.
    address public owner;
    address public securityExtension;

    mapping(address => bool) public extensions;

    event Sent(address indexed to, uint256 value, bytes data);
    event Received(address indexed from, uint256 value);
    event ExtensionAdded(address indexed extension);

    error VaultOnly();
    error AlreadyInitialized();
    error NotExtension();
    error CallFailed(bytes returndata);
    error ZeroAddress();

    modifier onlyExtension() {
        if (!extensions[msg.sender]) revert NotExtension();
        _;
    }

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Binds the owner and the permanent security module. Callable
    ///         once, only by the deployer, in the transaction that created
    ///         this wallet — there is no window without protection.
    function initialize(address _owner, address _securityExtension) external {
        if (msg.sender != deployer) revert VaultOnly();
        if (owner != address(0)) revert AlreadyInitialized();
        if (_owner == address(0) || _securityExtension == address(0)) revert ZeroAddress();
        owner = _owner;
        securityExtension = _securityExtension;
        extensions[_securityExtension] = true;
        emit ExtensionAdded(_securityExtension);
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

    /// @notice Owner-selected rotation is disabled: possession of a stolen
    ///         owner key must not evict the original owner from this vault.
    function rotateOwner(address) external pure { revert VaultOnly(); }

    /// @notice No bootstrap window: protection is installed by initialize().
    function addExtension(address) external pure { revert AlreadyInitialized(); }

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
