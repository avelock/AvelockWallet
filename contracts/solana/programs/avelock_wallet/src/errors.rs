use anchor_lang::prelude::*;

#[error_code]
pub enum AvelockError {
    #[msg("Owner cannot be the default/zero pubkey.")]
    ZeroAddress,
    #[msg("Delay values must be positive.")]
    ZeroMinimum,
    #[msg("Value is outside the permitted range for this parameter.")]
    InvalidParameter,
    #[msg("Initial value is below its immutable minimum.")]
    BelowImmutableMinimum,
    #[msg("Destination is not an active, allowed address.")]
    DestinationNotAllowed,
    #[msg("No pending change exists for this parameter.")]
    NoPendingChange,
    #[msg("The policy delay for this change has not elapsed yet.")]
    ChangeNotReady,
    #[msg("This request has already reached a final state.")]
    RequestAlreadyFinal,
    #[msg("This request's timelock has not elapsed yet.")]
    RequestNotReady,
    #[msg("This request's confirmation window has expired.")]
    RequestExpired,
    #[msg("This request is not yet eligible for pruning.")]
    RequestNotPrunable,
    #[msg("This request does not reference native SOL.")]
    NotNativeRequest,
    #[msg("This request does not reference the provided mint.")]
    AssetMismatch,
    #[msg("Amount must be greater than zero.")]
    ZeroAmount,
    #[msg("Withdrawal would spend the Vault's required rent deposit or exceeds its balance.")]
    InsufficientSpendableBalance,
    #[msg("Lamport arithmetic overflow.")]
    ArithmeticOverflow,
    #[msg("The Vault cannot be its own native withdrawal destination.")]
    InvalidDestination,
}
