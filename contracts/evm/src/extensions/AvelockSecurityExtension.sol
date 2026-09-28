// SPDX-License-Identifier: GPL-3.0-only
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
///
///      Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2; `features()`
///      bit 0). A guard can only stop things: cancel, lock. It can never
///      move funds, add a destination or a guard, change settings or
///      unlock. Locking is instant; unlocking waits `lockDelay`. The trust
///      model is still v0 (the phrase is the owner), hence version 0.
contract AvelockSecurityExtension is IExtension {
    /// @notice Bit 0: guard keys and Panic Lock.
    uint256 public constant FEATURE_GUARDS_AND_LOCK = 1;

    function protocolVersion() external pure returns (uint256) {
        return 0;
    }

    function features() external pure returns (uint256) {
        return FEATURE_GUARDS_AND_LOCK;
    }

    uint256 public constant MAX_DELAY = 90 days;
    uint256 public constant MAX_CONFIRMATION_WINDOW = 30 days;
    /// @dev How long a terminal request (cancelled or executed) is kept
    ///      before it can be pruned — bounds unbounded storage growth
    ///      from years of use without erasing recent history.
    uint256 public constant REQUEST_RETENTION = 182 days;
    uint256 public constant MAX_GUARDS = 2;
    /// @dev Default wait before an owner can lift a Panic Lock (at least the withdrawal delay).
    uint256 public constant DEFAULT_LOCK_DELAY = 7 days;

    enum Param {
        WithdrawalDelay,
        AddressDelay,
        ConfirmationWindow,
        PolicyDelay,
        LockDelay
    }

    struct Guard {
        address key;
        uint64 activeAt; // usable from this time (added keys wait addressDelay)
        uint64 removableAt; // 0 = no removal queued
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

    /// @dev The only address allowed to initialize (the factory for clones).
    address public immutable deployer;

    address public walletAddress;

    /// @dev Permanent floors set once at deployment. No setter, no
    ///      governance path, no policy-delay bypass can ever push
    ///      withdrawalDelay/addressDelay below these — see threat-model
    ///      section 14 ("Immutable Minimum"). A Vault meant to hold funds
    ///      for years should set these deliberately high at creation.
    uint256 public minWithdrawalDelay;
    uint256 public minAddressDelay;

    uint256 public withdrawalDelay;
    uint256 public addressDelay;
    uint256 public confirmationWindow;
    uint256 public policyDelay;

    /// @dev All parameter changes wait the current policy delay and obey fixed caps.
    mapping(Param => PendingParamChange) public pendingParamChanges;

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

    // ---- Guard keys and Panic Lock (version 1) ----
    Guard[2] internal guardSlots;
    uint256 public lockDelay;
    bool public locked;
    /// @dev The owner may unlock from this time on (while `locked`).
    uint256 public unlockAfter;
    /// @dev Bumped by every lock; requests and pending allowlist entries from
    ///      before a lock can no longer be used.
    uint256 public lockEpoch;
    mapping(uint256 => uint256) public lockTimeOfEpoch;
    mapping(uint256 => uint256) public requestLockEpoch;
    mapping(address => uint256) public allowlistLockEpoch;

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
    event RequestPruned(uint256 indexed requestId);
    event GuardAdded(address indexed key, uint256 activeAt);
    event GuardRemovalQueued(address indexed key, uint256 removableAt);
    event GuardRemovalCancelled(address indexed key);
    event GuardRemoved(address indexed key);
    event Locked(address indexed by, uint256 unlockAfter);
    event Unlocked();

    error OwnerRotationDisabled();
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
    error AlreadyInitialized();
    error VaultLocked();
    error NftTransferFailed();
    error NotLocked();
    error LockNotExpired();
    error TooManyGuards();
    error GuardNotFound();
    error GuardExists();
    error RequestAnnulled();
    error NotPending();

    modifier onlyOwner() {
        if (msg.sender != IAvelockWallet(walletAddress).owner()) revert NotOwner();
        _;
    }

    /// @dev The owner, or an active guard key (stop-only actions).
    modifier onlyOwnerOrGuard() {
        if (msg.sender != IAvelockWallet(walletAddress).owner() && !isGuard(msg.sender)) revert NotOwner();
        _;
    }

    modifier whenUnlocked() {
        if (locked) revert VaultLocked();
        _;
    }

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Sets the wallet and the initial policy. Callable once, only by
    ///         the deployer, in the transaction that created this module.
    ///         The minimums are permanent: nothing can write them again.
    function initialize(
        address _wallet,
        uint256 _withdrawalDelay,
        uint256 _addressDelay,
        uint256 _confirmationWindow,
        uint256 _policyDelay,
        uint256 _minWithdrawalDelay,
        uint256 _minAddressDelay
    ) external {
        if (msg.sender != deployer) revert NotOwner();
        if (walletAddress != address(0)) revert AlreadyInitialized();
        if (_wallet == address(0)) revert ZeroAddress();
        if (_withdrawalDelay < _minWithdrawalDelay) revert BelowImmutableMinimum();
        if (_addressDelay < _minAddressDelay) revert BelowImmutableMinimum();

        if (_minWithdrawalDelay == 0 || _minAddressDelay == 0) revert InvalidParameter();
        _validate(Param.WithdrawalDelay, _withdrawalDelay);
        _validate(Param.AddressDelay, _addressDelay);
        _validate(Param.ConfirmationWindow, _confirmationWindow);
        _validate(Param.PolicyDelay, _policyDelay);
        walletAddress = _wallet;
        // Lifting a lock waits at least as long as a withdrawal would.
        lockDelay = _withdrawalDelay > DEFAULT_LOCK_DELAY ? _withdrawalDelay : DEFAULT_LOCK_DELAY;
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

    function setWithdrawalDelay(uint256 newValue) external onlyOwner whenUnlocked {
        if (newValue < minWithdrawalDelay) revert BelowImmutableMinimum();
        _proposeChange(Param.WithdrawalDelay, newValue, withdrawalDelay);
    }

    function setAddressDelay(uint256 newValue) external onlyOwner whenUnlocked {
        if (newValue < minAddressDelay) revert BelowImmutableMinimum();
        _proposeChange(Param.AddressDelay, newValue, addressDelay);
    }

    function setConfirmationWindow(uint256 newValue) external onlyOwner whenUnlocked {
        _proposeChange(Param.ConfirmationWindow, newValue, confirmationWindow);
    }

    function setPolicyDelay(uint256 newValue) external onlyOwner whenUnlocked {
        _proposeChange(Param.PolicyDelay, newValue, policyDelay);
    }

    /// @notice The wait before a Panic Lock can be lifted; never below the withdrawal delay floor.
    function setLockDelay(uint256 newValue) external onlyOwner whenUnlocked {
        if (newValue < minWithdrawalDelay) revert BelowImmutableMinimum();
        _proposeChange(Param.LockDelay, newValue, lockDelay);
    }

    /// @notice Finalize a bounded parameter change after the old policy delay.
    function applyParamChange(Param param) external onlyOwner whenUnlocked {
        PendingParamChange storage p = pendingParamChanges[param];
        if (!p.exists) revert NoPendingChange();
        if (block.timestamp < p.effectiveAt) revert ChangeNotReady();

        // Copy before the delete: `p` is a storage reference, so after it the
        // event would carry 0 instead of the applied value (AVL-EVM-001).
        uint256 newValue = p.newValue;
        // The event carries what was actually written: a lockDelay below the
        // withdrawal delay is stored as the withdrawal delay (A12-3 review).
        uint256 written = _writeParam(param, newValue);
        delete pendingParamChanges[param];
        emit ParamChangeApplied(param, written);
    }

    /// @notice Cancel a queued parameter change before it takes effect (owner or guard).
    function cancelParamChange(Param param) external onlyOwnerOrGuard {
        if (!pendingParamChanges[param].exists) revert NoPendingChange();
        delete pendingParamChanges[param];
        emit ParamChangeCancelled(param);
    }

    /// @notice Kept as rejecting selectors for callers of development builds.
    ///         Recovery needs an independent authority committed at creation;
    ///         delaying an owner-chosen replacement key does not provide that.
    function proposeOwnerRotation(address) external pure { revert OwnerRotationDisabled(); }
    function applyOwnerRotation() external pure { revert OwnerRotationDisabled(); }
    function cancelOwnerRotation() external pure { revert OwnerRotationDisabled(); }

    function _validate(Param param, uint256 value) internal pure {
        uint256 limit = param == Param.ConfirmationWindow ? MAX_CONFIRMATION_WINDOW : MAX_DELAY;
        if (value == 0 || value > limit) revert InvalidParameter();
    }

    /// @dev Every actual parameter change waits under the current policy, including increases.
    function _proposeChange(Param param, uint256 newValue, uint256 currentValue) internal {
        _validate(param, newValue);
        // Re-setting the current value withdraws any queued change for this
        // parameter, so an old pending weakening cannot survive it (audit M-1).
        if (newValue == currentValue) {
            if (pendingParamChanges[param].exists) {
                delete pendingParamChanges[param];
                emit ParamChangeCancelled(param);
            }
            return;
        }
        uint256 effectiveAt = block.timestamp + changeWait();
        pendingParamChanges[param] = PendingParamChange(newValue, effectiveAt, true);
        emit ParamChangeQueued(param, newValue, effectiveAt);
    }

    /// @notice How long a parameter change waits: the policy delay, but never
    ///         less than the withdrawal delay (audit A14-2). Otherwise a short
    ///         policy delay would let a phrase thief lower the withdrawal delay
    ///         and withdraw sooner than the delay the owner set.
    function changeWait() public view returns (uint256) {
        return policyDelay > withdrawalDelay ? policyDelay : withdrawalDelay;
    }

    /// @dev Invariant (audit A12-3): lockDelay >= withdrawalDelay, held when a
    ///      change applies — a lock must not lift sooner than a withdrawal
    ///      could complete, or a phrase thief shortens the recovery window.
    function _writeParam(Param param, uint256 value) internal returns (uint256 written) {
        written = value;
        if (param == Param.WithdrawalDelay) {
            withdrawalDelay = value;
            if (lockDelay < value) {
                lockDelay = value;
                emit ParamChangeApplied(Param.LockDelay, value);
            }
        } else if (param == Param.AddressDelay) {
            addressDelay = value;
        } else if (param == Param.ConfirmationWindow) {
            confirmationWindow = value;
        } else if (param == Param.PolicyDelay) {
            policyDelay = value;
        } else {
            written = value < withdrawalDelay ? withdrawalDelay : value;
            lockDelay = written;
        }
    }

    // ---------------------------------------------------------------
    // Allowlist — adding is a weakening action (delayed), removing is a
    // strengthening action (immediate). See threat-model section 8.
    // ---------------------------------------------------------------

    function addAllowedAddress(address destination) external onlyOwner whenUnlocked {
        if (destination == address(0)) revert ZeroAddress();
        if (allowlistActiveAt[destination] != 0) {
            // An entry voided by a lock may be added again (and waits again).
            if (!_voidedByLock(destination)) return;
            allowlistEpoch[destination]++;
        }
        uint256 activeAt = block.timestamp + addressDelay;
        allowlistActiveAt[destination] = activeAt;
        allowlistLockEpoch[destination] = lockEpoch;
        emit AddressAdded(destination, activeAt);
    }

    /// @notice Stop a destination that is still waiting to become usable (owner or guard).
    function cancelPendingAddress(address destination) external onlyOwnerOrGuard {
        if (allowlistActiveAt[destination] <= block.timestamp) revert NotPending();
        allowlistEpoch[destination]++;
        delete allowlistActiveAt[destination];
        emit AddressRemoved(destination);
    }

    function removeAllowedAddress(address destination) external onlyOwner {
        allowlistEpoch[destination]++;
        delete allowlistActiveAt[destination];
        emit AddressRemoved(destination);
    }

    function isAddressActive(address destination) public view returns (bool) {
        uint256 activeAt = allowlistActiveAt[destination];
        return activeAt != 0 && block.timestamp >= activeAt && !_voidedByLock(destination);
    }

    /// @dev An entry still waiting when the first lock after it came is void:
    ///      a lock stops every pending change, new destinations included.
    function _voidedByLock(address destination) internal view returns (bool) {
        uint256 lockedAt = lockTimeOfEpoch[allowlistLockEpoch[destination] + 1];
        return lockedAt != 0 && lockedAt < allowlistActiveAt[destination];
    }

    // ---------------------------------------------------------------
    // Withdrawal lifecycle: request -> wait -> confirm -> execute
    // ---------------------------------------------------------------

    function requestWithdrawal(address to, address token, uint256 amount)
        external
        onlyOwner
        whenUnlocked
        returns (uint256 requestId)
    {
        return _request(to, token, amount, 0, 0);
    }

    function requestNFTWithdrawal(address to, address token, uint256 id, uint256 amount, bool is1155)
        external
        onlyOwner
        whenUnlocked
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
        requestLockEpoch[requestId] = lockEpoch;
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

    /// @notice Cancel a pending request at any time before execution (owner or guard).
    function cancelWithdrawal(uint256 requestId) external onlyOwnerOrGuard {
        WithdrawalRequest storage r = requests[requestId];
        if (r.to == address(0) && r.amount == 0 && r.availableAt == 0) revert RequestNotFound();
        if (r.executed || r.cancelled) revert RequestAlreadyFinal();

        r.cancelled = true;
        emit WithdrawalCancelled(requestId);
    }

    /// @notice Final confirmation after the timelock has elapsed. This is
    ///         a second, separate owner action — the timelock never
    ///         auto-executes (threat-model section 10).
    function confirmWithdrawal(uint256 requestId) external onlyOwner whenUnlocked {
        WithdrawalRequest storage r = requests[requestId];
        if (r.to == address(0) && r.amount == 0 && r.availableAt == 0) revert RequestNotFound();
        if (r.executed || r.cancelled) revert RequestAlreadyFinal();
        if (requestLockEpoch[requestId] != lockEpoch) revert RequestAnnulled();
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

        bool isErc20 = kind == 0 && r.token != address(0);
        uint256 balanceBefore = isErc20 ? _tokenBalance(r.token, walletAddress) : 0;
        uint256 heldBefore = kind == 2 ? _heldOf(r.token, walletAddress, tokenId[requestId]) : 0;

        emit WithdrawalExecuted(requestId);
        bytes memory returndata = IAvelockWallet(walletAddress).executeFromExtension(callTarget, callValue, data);

        // Tokens signal the result three ways: revert, `false`, or nothing.
        // Tether on TRON returns `false` even on success (audit H-5), so a
        // `false`/empty return is accepted only when the Vault's balance
        // actually dropped by the requested amount. `true` is trusted as-is.
        if (isErc20) {
            bool returnedTrue = returndata.length >= 32 && abi.decode(returndata, (bool));
            if (!returnedTrue) {
                uint256 balanceAfter = _tokenBalance(r.token, walletAddress);
                if (balanceAfter > balanceBefore || balanceBefore - balanceAfter != r.amount) revert Erc20TransferFailed();
            }
        }
        // An NFT contract that returns without moving the token must not
        // leave the request marked done (audit A15-9).
        if (kind == 1 && _ownerOf(r.token, tokenId[requestId]) != r.to) revert NftTransferFailed();
        if (kind == 2) {
            uint256 heldAfter = _heldOf(r.token, walletAddress, tokenId[requestId]);
            if (heldAfter > heldBefore || heldBefore - heldAfter != r.amount) revert NftTransferFailed();
        }
    }

    function _ownerOf(address token, uint256 id) private view returns (address) {
        (bool ok, bytes memory out) = token.staticcall(abi.encodeWithSignature("ownerOf(uint256)", id));
        if (!ok || out.length < 32) revert NftTransferFailed();
        return abi.decode(out, (address));
    }

    function _heldOf(address token, address holder, uint256 id) private view returns (uint256) {
        (bool ok, bytes memory out) = token.staticcall(abi.encodeWithSignature("balanceOf(address,uint256)", holder, id));
        if (!ok || out.length < 32) revert NftTransferFailed();
        return abi.decode(out, (uint256));
    }

    function _tokenBalance(address token, address holder) private view returns (uint256) {
        (bool ok, bytes memory out) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", holder));
        if (!ok || out.length < 32) revert Erc20TransferFailed();
        return abi.decode(out, (uint256));
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
        bool annulled = requestLockEpoch[requestId] != lockEpoch && !r.executed;
        bool terminal = r.executed || r.cancelled || annulled || block.timestamp > r.expiresAt;
        bool retentionOk = r.cancelled || annulled || block.timestamp > r.expiresAt + REQUEST_RETENTION;
        if (!terminal || !retentionOk) revert RequestNotReady();

        delete requests[requestId];
        delete requestEpoch[requestId];
        delete assetKind[requestId];
        delete tokenId[requestId];
        delete requestLockEpoch[requestId];
        emit RequestPruned(requestId);
    }

    /// @notice True when a lock after its creation voided the request.
    function isRequestAnnulled(uint256 requestId) external view returns (bool) {
        return requestLockEpoch[requestId] != lockEpoch && !requests[requestId].executed;
    }

    // ---------------------------------------------------------------
    // Guard keys: stop-only second keys (old phone, hardware key).
    // Adding and removing both wait addressDelay, so a stolen owner key
    // cannot quietly swap them; a guard cannot cancel its own removal.
    // ---------------------------------------------------------------

    function isGuard(address key) public view returns (bool) {
        if (key == address(0)) return false;
        for (uint256 i; i < MAX_GUARDS; i++) {
            Guard storage g = guardSlots[i];
            if (g.key == key) return block.timestamp >= g.activeAt;
        }
        return false;
    }

    function guards() external view returns (Guard[2] memory) {
        return guardSlots;
    }

    function addGuard(address key) external onlyOwner whenUnlocked {
        if (key == address(0)) revert ZeroAddress();
        if (key == IAvelockWallet(walletAddress).owner()) revert InvalidParameter();
        uint256 free = MAX_GUARDS;
        for (uint256 i; i < MAX_GUARDS; i++) {
            if (guardSlots[i].key == key) revert GuardExists();
            if (guardSlots[i].key == address(0) && free == MAX_GUARDS) free = i;
        }
        if (free == MAX_GUARDS) revert TooManyGuards();
        uint256 activeAt = block.timestamp + addressDelay;
        guardSlots[free] = Guard(key, uint64(activeAt), 0);
        emit GuardAdded(key, activeAt);
    }

    /// @notice A guard still waiting to become active is dropped at once
    ///         (owner or guard); an active one is queued for removal.
    function removeGuard(address key) external {
        uint256 i = _guardIndex(key);
        Guard storage g = guardSlots[i];
        bool owner = msg.sender == IAvelockWallet(walletAddress).owner();
        if (block.timestamp < g.activeAt) {
            if (!owner && !isGuard(msg.sender)) revert NotOwner();
            delete guardSlots[i];
            emit GuardRemoved(key);
            return;
        }
        if (!owner) revert NotOwner();
        // Queued only while unlocked, and a lock drops the queue (audit A15-1).
        if (locked) revert VaultLocked();
        if (g.removableAt != 0) return;
        uint256 removableAt = block.timestamp + addressDelay;
        g.removableAt = uint64(removableAt);
        emit GuardRemovalQueued(key, removableAt);
    }

    function cancelGuardRemoval(address key) external onlyOwner {
        Guard storage g = guardSlots[_guardIndex(key)];
        if (g.removableAt == 0) revert NotPending();
        g.removableAt = 0;
        emit GuardRemovalCancelled(key);
    }

    /// @dev Never during a lock (audit A15-1): otherwise a phrase thief queues
    ///      the removal, waits out the guard's lock, and no one is left to
    ///      extend it.
    function finalizeGuardRemoval(address key) external onlyOwner whenUnlocked {
        uint256 i = _guardIndex(key);
        uint256 removableAt = guardSlots[i].removableAt;
        if (removableAt == 0) revert NotPending();
        if (block.timestamp < removableAt) revert ChangeNotReady();
        delete guardSlots[i];
        emit GuardRemoved(key);
    }

    function _guardIndex(address key) internal view returns (uint256) {
        if (key != address(0)) {
            for (uint256 i; i < MAX_GUARDS; i++) if (guardSlots[i].key == key) return i;
        }
        revert GuardNotFound();
    }

    // ---------------------------------------------------------------
    // Panic Lock: instant to set (owner or guard), slow to lift.
    // Locking voids every pending request, queued setting change,
    // pending guard and pending destination. Locking again extends it.
    // ---------------------------------------------------------------

    function lock() external onlyOwnerOrGuard {
        uint256 until = block.timestamp + lockDelay;
        if (locked) {
            if (until > unlockAfter) unlockAfter = until;
            emit Locked(msg.sender, unlockAfter);
            return;
        }
        locked = true;
        unlockAfter = until;
        lockEpoch++;
        lockTimeOfEpoch[lockEpoch] = block.timestamp;
        for (uint256 p; p <= uint256(Param.LockDelay); p++) {
            if (pendingParamChanges[Param(p)].exists) {
                delete pendingParamChanges[Param(p)];
                emit ParamChangeCancelled(Param(p));
            }
        }
        for (uint256 i; i < MAX_GUARDS; i++) {
            Guard storage g = guardSlots[i];
            if (g.key != address(0) && block.timestamp < g.activeAt) {
                emit GuardRemoved(g.key);
                delete guardSlots[i];
            } else if (g.removableAt != 0) {
                // A queued removal of an active guard is void too (A15-1).
                g.removableAt = 0;
                emit GuardRemovalCancelled(g.key);
            }
        }
        emit Locked(msg.sender, until);
    }

    /// @notice Only the owner lifts a lock, and only after `unlockAfter`.
    function unlock() external onlyOwner {
        if (!locked) revert NotLocked();
        if (block.timestamp < unlockAfter) revert LockNotExpired();
        locked = false;
        emit Unlocked();
    }
}
