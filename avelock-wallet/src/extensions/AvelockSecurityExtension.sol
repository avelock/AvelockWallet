// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// ============================================================
// Avelock Wallet — Security Extension
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import {IExtension} from "../interfaces/IExtension.sol";

interface IAvelockWallet {
    function owner() external view returns (address);
    function executeFromExtension(address to, uint256 value, bytes calldata data) external returns (bytes memory);
    function rotateOwner(address newOwner) external;
}

/// @title AvelockSecurityExtension
/// @notice The first Vault module: request -> delay -> confirm -> execute
///         withdrawals, plus an address allowlist with its own activation
///         delay. Permanently bound to an AvelockWallet at deployment.
/// @dev Scope of this iteration: Withdrawal Delay, Address Delay, Final
///      Confirmation Window, allowlist add (delayed) / remove (immediate),
///      cancel, a Security Policy Delay gating any weakening change to
///      those parameters (threat-model section 13), and immutable floors
///      on withdrawalDelay/addressDelay that no owner action — not even a
///      policy-delayed one — can ever go below (threat-model section 14).
contract AvelockSecurityExtension is IExtension {
    function protocolVersion() external pure returns (uint256) {
        return 4;
    }

    uint256 public constant MAX_DELAY = 90 days;
    uint256 public constant MAX_CONFIRMATION_WINDOW = 30 days;
    /// @dev How long a terminal request (cancelled or executed) is kept
    ///      before it can be pruned — bounds unbounded storage growth
    ///      from years of use without erasing recent history.
    uint256 public constant REQUEST_RETENTION = 182 days;

    enum Param {
        WithdrawalDelay,
        AddressDelay,
        ConfirmationWindow,
        PolicyDelay
    }

    struct PendingParamChange {
        uint256 newValue;
        uint256 effectiveAt;
        bool exists;
    }

    struct WithdrawalRequest {
        address to;
        address token; // address(0) == native ETH
        uint256 amount;
        uint256 availableAt;
        uint256 expiresAt;
        bool executed;
        bool cancelled;
    }

    address public immutable walletAddress;

    /// @dev Permanent floors set once at deployment. No setter, no
    ///      governance path, no policy-delay bypass can ever push
    ///      withdrawalDelay/addressDelay below these — see threat-model
    ///      section 14 ("Immutable Minimum"). A Vault meant to hold funds
    ///      for years should set these deliberately high at creation.
    uint256 public immutable minWithdrawalDelay;
    uint256 public immutable minAddressDelay;

    uint256 public withdrawalDelay;
    uint256 public addressDelay;
    uint256 public confirmationWindow;
    uint256 public policyDelay;

    /// @dev All parameter changes wait the current policy delay and obey fixed caps.
    mapping(Param => PendingParamChange) public pendingParamChanges;

    /// @dev A delayed owner-key rotation, gated by the same policyDelay as
    ///      any other change. There is no faster path: a compromised key
    ///      can be raced out (by whoever notices and signs first), never
    ///      instantly revoked — see threat-model on key compromise.
    address public pendingOwner;
    uint256 public pendingOwnerEffectiveAt;
    bool public pendingOwnerExists;

    /// @dev 0 = never added; >0 = timestamp at which the address becomes
    ///      usable as a withdrawal destination.
    mapping(address => uint256) public allowlistActiveAt;

    uint256 public nextRequestId;
    mapping(uint256 => WithdrawalRequest) public requests;
    mapping(address => uint256) public allowlistEpoch;
    mapping(uint256 => uint256) public requestEpoch;
    // 0: native/ERC20; 1: ERC721; 2: ERC1155. Separate maps preserve the request getter ABI.
    mapping(uint256 => uint8) public assetKind;
    mapping(uint256 => uint256) public tokenId;

    event AddressAdded(address indexed destination, uint256 activeAt);
    event AddressRemoved(address indexed destination);
    event WithdrawalRequested(
        uint256 indexed requestId,
        address indexed to,
        address token,
        uint256 amount,
        uint256 availableAt,
        uint256 expiresAt
    );
    event WithdrawalCancelled(uint256 indexed requestId);
    event WithdrawalExecuted(uint256 indexed requestId);
    event ParamChangeApplied(Param indexed param, uint256 newValue);
    event ParamChangeQueued(Param indexed param, uint256 newValue, uint256 effectiveAt);
    event ParamChangeCancelled(Param indexed param);
    event OwnerRotationQueued(address indexed newOwner, uint256 effectiveAt);
    event OwnerRotationApplied(address indexed newOwner);
    event OwnerRotationCancelled(address indexed cancelledOwner);
    event RequestPruned(uint256 indexed requestId);

    error InvalidParameter();
    error InvalidAsset();
    error NotOwner();
    error DestinationNotAllowed();
    error RequestNotFound();
    error RequestNotReady();
    error RequestExpired();
    error RequestAlreadyFinal();
    error ZeroAddress();
    error NoPendingChange();
    error ChangeNotReady();
    error BelowImmutableMinimum();
    error Erc20TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != IAvelockWallet(walletAddress).owner()) revert NotOwner();
        _;
    }

    constructor(
        address _wallet,
        uint256 _withdrawalDelay,
        uint256 _addressDelay,
        uint256 _confirmationWindow,
        uint256 _policyDelay,
        uint256 _minWithdrawalDelay,
        uint256 _minAddressDelay
    ) {
        if (_wallet == address(0)) revert ZeroAddress();
        if (_withdrawalDelay < _minWithdrawalDelay) revert BelowImmutableMinimum();
        if (_addressDelay < _minAddressDelay) revert BelowImmutableMinimum();

        if (_minWithdrawalDelay == 0 || _minAddressDelay == 0) revert InvalidParameter();
        _validate(Param.WithdrawalDelay, _withdrawalDelay);
        _validate(Param.AddressDelay, _addressDelay);
        _validate(Param.ConfirmationWindow, _confirmationWindow);
        _validate(Param.PolicyDelay, _policyDelay);
        walletAddress = _wallet;
        withdrawalDelay = _withdrawalDelay;
        addressDelay = _addressDelay;
        confirmationWindow = _confirmationWindow;
        policyDelay = _policyDelay;
        minWithdrawalDelay = _minWithdrawalDelay;
        minAddressDelay = _minAddressDelay;
    }

    function wallet() external view returns (address) {
        return walletAddress;
    }

    // ---------------------------------------------------------------
    // All policy changes are delayed, including increases that can harm availability.
    // ---------------------------------------------------------------

    function setWithdrawalDelay(uint256 newValue) external onlyOwner {
        if (newValue < minWithdrawalDelay) revert BelowImmutableMinimum();
        _proposeChange(Param.WithdrawalDelay, newValue, withdrawalDelay);
    }

    function setAddressDelay(uint256 newValue) external onlyOwner {
        if (newValue < minAddressDelay) revert BelowImmutableMinimum();
        _proposeChange(Param.AddressDelay, newValue, addressDelay);
    }

    function setConfirmationWindow(uint256 newValue) external onlyOwner {
        _proposeChange(Param.ConfirmationWindow, newValue, confirmationWindow);
    }

    function setPolicyDelay(uint256 newValue) external onlyOwner {
        _proposeChange(Param.PolicyDelay, newValue, policyDelay);
    }

    /// @notice Finalize a bounded parameter change after the old policy delay.
    function applyParamChange(Param param) external onlyOwner {
        PendingParamChange storage p = pendingParamChanges[param];
        if (!p.exists) revert NoPendingChange();
        if (block.timestamp < p.effectiveAt) revert ChangeNotReady();

        _writeParam(param, p.newValue);
        delete pendingParamChanges[param];
        emit ParamChangeApplied(param, p.newValue);
    }

    /// @notice Cancel a queued parameter change before it takes effect.
    function cancelParamChange(Param param) external onlyOwner {
        if (!pendingParamChanges[param].exists) revert NoPendingChange();
        delete pendingParamChanges[param];
        emit ParamChangeCancelled(param);
    }

    // ---------------------------------------------------------------
    // Owner-key rotation — the only way to move off a key without
    // instantly handing equal, permanent power to whoever holds it if
    // it's stolen. Gated by the current policyDelay, same as any other
    // change; a compromised key can still race a legitimate rotation
    // (whoever signs first wins), it just can no longer act forever.
    // ---------------------------------------------------------------

    function proposeOwnerRotation(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        pendingOwnerEffectiveAt = block.timestamp + policyDelay;
        pendingOwnerExists = true;
        emit OwnerRotationQueued(newOwner, pendingOwnerEffectiveAt);
    }

    function applyOwnerRotation() external onlyOwner {
        if (!pendingOwnerExists) revert NoPendingChange();
        if (block.timestamp < pendingOwnerEffectiveAt) revert ChangeNotReady();
        address newOwner = pendingOwner;
        pendingOwnerExists = false;
        delete pendingOwner;
        delete pendingOwnerEffectiveAt;
        IAvelockWallet(walletAddress).rotateOwner(newOwner);
        emit OwnerRotationApplied(newOwner);
    }

    function cancelOwnerRotation() external onlyOwner {
        if (!pendingOwnerExists) revert NoPendingChange();
        address cancelled = pendingOwner;
        pendingOwnerExists = false;
        delete pendingOwner;
        delete pendingOwnerEffectiveAt;
        emit OwnerRotationCancelled(cancelled);
    }

    function _validate(Param param, uint256 value) internal pure {
        uint256 limit = param == Param.ConfirmationWindow ? MAX_CONFIRMATION_WINDOW : MAX_DELAY;
        if (value == 0 || value > limit) revert InvalidParameter();
    }

    /// @dev Every actual parameter change waits under the current policy, including increases.
    function _proposeChange(Param param, uint256 newValue, uint256 currentValue) internal {
        _validate(param, newValue);
        if (newValue == currentValue) return;
        uint256 effectiveAt = block.timestamp + policyDelay;
        pendingParamChanges[param] = PendingParamChange(newValue, effectiveAt, true);
        emit ParamChangeQueued(param, newValue, effectiveAt);
    }

    function _writeParam(Param param, uint256 value) internal {
        if (param == Param.WithdrawalDelay) {
            withdrawalDelay = value;
        } else if (param == Param.AddressDelay) {
            addressDelay = value;
        } else if (param == Param.ConfirmationWindow) {
            confirmationWindow = value;
        } else {
            policyDelay = value;
        }
    }

    // ---------------------------------------------------------------
    // Allowlist — adding is a weakening action (delayed), removing is a
    // strengthening action (immediate). See threat-model section 8.
    // ---------------------------------------------------------------

    function addAllowedAddress(address destination) external onlyOwner {
        if (destination == address(0)) revert ZeroAddress();
        if (allowlistActiveAt[destination] != 0) return;
        uint256 activeAt = block.timestamp + addressDelay;
        allowlistActiveAt[destination] = activeAt;
        emit AddressAdded(destination, activeAt);
    }

    function removeAllowedAddress(address destination) external onlyOwner {
        allowlistEpoch[destination]++;
        delete allowlistActiveAt[destination];
        emit AddressRemoved(destination);
    }

    function isAddressActive(address destination) public view returns (bool) {
        uint256 activeAt = allowlistActiveAt[destination];
        return activeAt != 0 && block.timestamp >= activeAt;
    }

    // ---------------------------------------------------------------
    // Withdrawal lifecycle: request -> wait -> confirm -> execute
    // ---------------------------------------------------------------

    function requestWithdrawal(address to, address token, uint256 amount)
        external
        onlyOwner
        returns (uint256 requestId)
    {
        return _request(to, token, amount, 0, 0);
    }

    function requestNFTWithdrawal(address to, address token, uint256 id, uint256 amount, bool is1155)
        external
        onlyOwner
        returns (uint256)
    {
        if (token == address(0) || (!is1155 && amount != 1)) revert InvalidAsset();
        return _request(to, token, amount, is1155 ? 2 : 1, id);
    }

    function _request(address to, address token, uint256 amount, uint8 kind, uint256 id)
        internal
        returns (uint256 requestId)
    {
        if (!isAddressActive(to)) revert DestinationNotAllowed();
        if (amount == 0 || (token != address(0) && token.code.length == 0)) revert InvalidAsset();

        requestId = nextRequestId++;
        requestEpoch[requestId] = allowlistEpoch[to];
        assetKind[requestId] = kind;
        tokenId[requestId] = id;
        uint256 availableAt = block.timestamp + withdrawalDelay;
        uint256 expiresAt = availableAt + confirmationWindow;

        requests[requestId] = WithdrawalRequest({
            to: to,
            token: token,
            amount: amount,
            availableAt: availableAt,
            expiresAt: expiresAt,
            executed: false,
            cancelled: false
        });

        emit WithdrawalRequested(requestId, to, token, amount, availableAt, expiresAt);
    }

    /// @notice Cancel a pending request at any time before execution.
    function cancelWithdrawal(uint256 requestId) external onlyOwner {
        WithdrawalRequest storage r = requests[requestId];
        if (r.to == address(0) && r.amount == 0 && r.availableAt == 0) revert RequestNotFound();
        if (r.executed || r.cancelled) revert RequestAlreadyFinal();

        r.cancelled = true;
        emit WithdrawalCancelled(requestId);
    }

    /// @notice Final confirmation after the timelock has elapsed. This is
    ///         a second, separate owner action — the timelock never
    ///         auto-executes (threat-model section 10).
    function confirmWithdrawal(uint256 requestId) external onlyOwner {
        WithdrawalRequest storage r = requests[requestId];
        if (r.to == address(0) && r.amount == 0 && r.availableAt == 0) revert RequestNotFound();
        if (r.executed || r.cancelled) revert RequestAlreadyFinal();
        if (block.timestamp < r.availableAt) revert RequestNotReady();
        if (block.timestamp > r.expiresAt) revert RequestExpired();

        if (!isAddressActive(r.to) || requestEpoch[requestId] != allowlistEpoch[r.to]) revert DestinationNotAllowed();
        r.executed = true;

        bytes memory data;
        uint8 kind = assetKind[requestId];
        if (kind == 1) {
            data = abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256)", walletAddress, r.to, tokenId[requestId]
            );
        } else if (kind == 2) {
            data = abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256,uint256,bytes)",
                walletAddress,
                r.to,
                tokenId[requestId],
                r.amount,
                bytes("")
            );
        } else if (r.token == address(0)) {
            data = "";
        } else {
            data = abi.encodeWithSignature("transfer(address,uint256)", r.to, r.amount);
        }

        address callTarget = r.token == address(0) ? r.to : r.token;
        uint256 callValue = r.token == address(0) ? r.amount : 0;

        emit WithdrawalExecuted(requestId);
        bytes memory returndata = IAvelockWallet(walletAddress).executeFromExtension(callTarget, callValue, data);

        // Some ERC-20s (e.g. threat-model section 50: "tokens that return
        // false") signal failure via a bool return instead of reverting.
        // A plain low-level call treats that as success, so we decode and
        // check it ourselves — reverting here unwinds the whole tx,
        // including the token call, since nothing has been persisted
        // externally yet.
        if (kind == 0 && r.token != address(0) && returndata.length > 0) {
            bool success = abi.decode(returndata, (bool));
            if (!success) revert Erc20TransferFailed();
        }
    }

    /// @notice Remove a terminal request's storage once it has aged past
    ///         the retention window. Without this, every successfully
    ///         executed or cancelled request would accumulate in storage
    ///         forever. IDs are never reused, so pruning never creates
    ///         ambiguity with a future request.
    function pruneRequest(uint256 requestId) external onlyOwner {
        WithdrawalRequest storage r = requests[requestId];
        if (r.to == address(0) && r.amount == 0 && r.availableAt == 0) revert RequestNotFound();
        // A cancelled request never moved anything and may be removed
        // immediately. An executed (settled) or expired-unconfirmed one
        // waits out the retention window first, so a completed
        // withdrawal's record stays available for audit for a while.
        bool terminal = r.executed || r.cancelled || block.timestamp > r.expiresAt;
        bool retentionOk = r.cancelled || block.timestamp > r.expiresAt + REQUEST_RETENTION;
        if (!terminal || !retentionOk) revert RequestNotReady();

        delete requests[requestId];
        delete requestEpoch[requestId];
        delete assetKind[requestId];
        delete tokenId[requestId];
        emit RequestPruned(requestId);
    }
}
