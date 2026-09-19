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
}

/// @title AvelockSecurityExtension
/// @notice The first Vault module: request -> delay -> confirm -> execute
///         withdrawals, plus an address allowlist with its own activation
///         delay. Authorized on an AvelockWallet via addExtension(), so the
///         base wallet core never changes when this logic evolves.
/// @dev Scope of this iteration: Withdrawal Delay, Address Delay, Final
///      Confirmation Window, allowlist add (delayed) / remove (immediate),
///      cancel, a Security Policy Delay gating any weakening change to
///      those parameters (threat-model section 13), and immutable floors
///      on withdrawalDelay/addressDelay that no owner action — not even a
///      policy-delayed one — can ever go below (threat-model section 14).
contract AvelockSecurityExtension is IExtension {
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

    /// @dev A higher delay value is always the stronger setting for these
    ///      parameters, so raising one applies immediately and lowering
    ///      one queues a PendingParamChange gated by the CURRENT
    ///      policyDelay (never the new one — see threat-model section 13).
    mapping(Param => PendingParamChange) public pendingParamChanges;

    /// @dev 0 = never added; >0 = timestamp at which the address becomes
    ///      usable as a withdrawal destination.
    mapping(address => uint256) public allowlistActiveAt;

    uint256 public nextRequestId;
    mapping(uint256 => WithdrawalRequest) public requests;

    event AddressAdded(address indexed destination, uint256 activeAt);
    event AddressRemoved(address indexed destination);
    event WithdrawalRequested(
        uint256 indexed requestId, address indexed to, address token, uint256 amount, uint256 availableAt, uint256 expiresAt
    );
    event WithdrawalCancelled(uint256 indexed requestId);
    event WithdrawalExecuted(uint256 indexed requestId);
    event ParamChangeApplied(Param indexed param, uint256 newValue);
    event ParamChangeQueued(Param indexed param, uint256 newValue, uint256 effectiveAt);
    event ParamChangeCancelled(Param indexed param);

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
    // Security Policy Delay — raising a delay strengthens the vault and
    // takes effect immediately; lowering one weakens it and must wait out
    // the CURRENT policyDelay (threat-model section 13: changing the
    // policy delay itself follows the OLD rule, not the new one, so it
    // can't be used to fast-track other weakenings).
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

    /// @notice Finalize a queued weakening change once its delay has
    ///         elapsed. A strengthening change never queues — it is
    ///         applied immediately by the setter above.
    function applyParamChange(Param param) external onlyOwner {
        PendingParamChange storage p = pendingParamChanges[param];
        if (!p.exists) revert NoPendingChange();
        if (block.timestamp < p.effectiveAt) revert ChangeNotReady();

        _writeParam(param, p.newValue);
        delete pendingParamChanges[param];
        emit ParamChangeApplied(param, p.newValue);
    }

    /// @notice Cancel a queued weakening change before it takes effect.
    function cancelParamChange(Param param) external onlyOwner {
        if (!pendingParamChanges[param].exists) revert NoPendingChange();
        delete pendingParamChanges[param];
        emit ParamChangeCancelled(param);
    }

    function _proposeChange(Param param, uint256 newValue, uint256 currentValue) internal {
        if (newValue >= currentValue) {
            // Strengthening (or no-op): apply immediately, drop any stale
            // pending weakening for this param.
            delete pendingParamChanges[param];
            _writeParam(param, newValue);
            emit ParamChangeApplied(param, newValue);
        } else {
            uint256 effectiveAt = block.timestamp + policyDelay;
            pendingParamChanges[param] = PendingParamChange({newValue: newValue, effectiveAt: effectiveAt, exists: true});
            emit ParamChangeQueued(param, newValue, effectiveAt);
        }
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
        uint256 activeAt = block.timestamp + addressDelay;
        allowlistActiveAt[destination] = activeAt;
        emit AddressAdded(destination, activeAt);
    }

    function removeAllowedAddress(address destination) external onlyOwner {
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

    function requestWithdrawal(address to, address token, uint256 amount) external onlyOwner returns (uint256 requestId) {
        if (!isAddressActive(to)) revert DestinationNotAllowed();

        requestId = nextRequestId++;
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

        r.executed = true;

        bytes memory data;
        if (r.token == address(0)) {
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
        if (r.token != address(0) && returndata.length > 0) {
            bool success = abi.decode(returndata, (bool));
            if (!success) revert Erc20TransferFailed();
        }
    }
}
