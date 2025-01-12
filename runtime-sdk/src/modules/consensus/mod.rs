//! Consensus module.
//!
//! Low level consensus module for communicating with the consensus layer.
use std::str::FromStr;

use thiserror::Error;

use oasis_core_runtime::{
    common::versioned::Versioned,
    consensus::{
        roothash::{Message, StakingMessage},
        staking,
        staking::Account as ConsensusAccount,
        state::{staking::ImmutableState as StakingImmutableState, StateError},
    },
};

use crate::{
    context::{Context, TxContext},
    module,
    module::Module as _,
    modules,
    modules::core::{Module as Core, API as _},
    types::{
        address::{Address, SignatureAddressSpec},
        message::MessageEventHookInvocation,
        token,
        transaction::{AddressSpec, TransactionWeight},
    },
};

#[cfg(test)]
mod test;

/// Unique module name.
const MODULE_NAME: &str = "consensus";

/// Parameters for the consensus module.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct Parameters {
    pub consensus_denomination: token::Denomination,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            consensus_denomination: token::Denomination::from_str("TEST").unwrap(),
        }
    }
}

impl module::Parameters for Parameters {
    type Error = ();
}
/// Events emitted by the consensus module (none so far).
#[derive(Debug, cbor::Encode, oasis_runtime_sdk_macros::Event)]
#[cbor(untagged)]
pub enum Event {}

/// Genesis state for the consensus module.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Genesis {
    pub parameters: Parameters,
}

#[derive(Error, Debug, oasis_runtime_sdk_macros::Error)]
pub enum Error {
    #[error("invalid argument")]
    #[sdk_error(code = 1)]
    InvalidArgument,

    #[error("invalid denomination")]
    #[sdk_error(code = 2)]
    InvalidDenomination,

    #[error("internal state: {0}")]
    #[sdk_error(code = 3)]
    InternalStateError(#[from] StateError),

    #[error("core: {0}")]
    #[sdk_error(transparent)]
    Core(#[from] modules::core::Error),

    #[error("consensus incompatible signer")]
    #[sdk_error(code = 4)]
    ConsensusIncompatibleSigner,
}

/// Interface that can be called from other modules.
pub trait API {
    /// Transfer an amount from the runtime account.
    fn transfer<C: TxContext>(
        ctx: &mut C,
        to: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error>;

    /// Withdraw an amount into the runtime account.
    fn withdraw<C: TxContext>(
        ctx: &mut C,
        from: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error>;

    /// Escrow an amount of the runtime account funds.
    fn escrow<C: TxContext>(
        ctx: &mut C,
        to: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error>;

    /// Reclaim an amount of runtime staked shares.
    fn reclaim_escrow<C: TxContext>(
        ctx: &mut C,
        from: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error>;

    /// Returns consensus token denomination.
    fn consensus_denomination<C: Context>(ctx: &mut C) -> Result<token::Denomination, Error>;

    /// Ensures transaction signer is consensus compatible.
    fn ensure_compatible_tx_signer<C: TxContext>(ctx: &C) -> Result<(), Error>;

    /// Query consensus account info.
    fn account<C: Context>(ctx: &C, addr: Address) -> Result<ConsensusAccount, Error>;
}

pub struct Module;

impl Module {
    fn ensure_consensus_denomination<C: Context>(
        ctx: &mut C,
        denomination: &token::Denomination,
    ) -> Result<(), Error> {
        if denomination != &Self::consensus_denomination(ctx)? {
            return Err(Error::InvalidDenomination);
        }

        Ok(())
    }
}

impl API for Module {
    fn transfer<C: TxContext>(
        ctx: &mut C,
        to: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error> {
        Self::ensure_consensus_denomination(ctx, amount.denomination())?;

        Core::add_weight(ctx, TransactionWeight::ConsensusMessages, 1)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        ctx.emit_message(
            Message::Staking(Versioned::new(
                0,
                StakingMessage::Transfer(staking::Transfer {
                    to: to.into(),
                    amount: amount.amount().into(),
                }),
            )),
            hook,
        )?;

        Ok(())
    }

    fn withdraw<C: TxContext>(
        ctx: &mut C,
        from: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error> {
        Self::ensure_consensus_denomination(ctx, amount.denomination())?;

        Core::add_weight(ctx, TransactionWeight::ConsensusMessages, 1)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        ctx.emit_message(
            Message::Staking(Versioned::new(
                0,
                StakingMessage::Withdraw(staking::Withdraw {
                    from: from.into(),
                    amount: amount.amount().into(),
                }),
            )),
            hook,
        )?;

        Ok(())
    }

    fn escrow<C: TxContext>(
        ctx: &mut C,
        to: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error> {
        Self::ensure_consensus_denomination(ctx, amount.denomination())?;

        Core::add_weight(ctx, TransactionWeight::ConsensusMessages, 1)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        ctx.emit_message(
            Message::Staking(Versioned::new(
                0,
                StakingMessage::AddEscrow(staking::Escrow {
                    account: to.into(),
                    amount: amount.amount().into(),
                }),
            )),
            hook,
        )?;

        Ok(())
    }

    fn reclaim_escrow<C: TxContext>(
        ctx: &mut C,
        from: Address,
        amount: &token::BaseUnits,
        hook: MessageEventHookInvocation,
    ) -> Result<(), Error> {
        Self::ensure_consensus_denomination(ctx, amount.denomination())?;

        Core::add_weight(ctx, TransactionWeight::ConsensusMessages, 1)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        ctx.emit_message(
            Message::Staking(Versioned::new(
                0,
                StakingMessage::ReclaimEscrow(staking::ReclaimEscrow {
                    account: from.into(),
                    shares: amount.amount().into(),
                }),
            )),
            hook,
        )?;

        Ok(())
    }

    fn consensus_denomination<C: Context>(ctx: &mut C) -> Result<token::Denomination, Error> {
        let params = Self::params(ctx.runtime_state());
        Ok(params.consensus_denomination)
    }

    fn ensure_compatible_tx_signer<C: TxContext>(ctx: &C) -> Result<(), Error> {
        match ctx.tx_auth_info().signer_info[0].address_spec {
            AddressSpec::Signature(SignatureAddressSpec::Ed25519(_)) => Ok(()),
            _ => Err(Error::ConsensusIncompatibleSigner),
        }
    }

    fn account<C: Context>(ctx: &C, addr: Address) -> Result<ConsensusAccount, Error> {
        let state = StakingImmutableState::new(ctx.consensus_state());
        state
            .account(ctx.io_ctx(), addr.into())
            .map_err(Error::InternalStateError)
    }
}

impl module::Module for Module {
    const NAME: &'static str = MODULE_NAME;
    const VERSION: u32 = 1;
    type Error = Error;
    type Event = Event;
    type Parameters = Parameters;
}

impl module::MethodHandler for Module {}

impl module::MigrationHandler for Module {
    type Genesis = Genesis;

    fn init_or_migrate<C: Context>(
        ctx: &mut C,
        meta: &mut modules::core::types::Metadata,
        genesis: Self::Genesis,
    ) -> bool {
        let version = meta.versions.get(Self::NAME).copied().unwrap_or_default();
        if version == 0 {
            // TODO: enable loading consensus denomination from consensus state after:
            // https://github.com/oasisprotocol/oasis-core/issues/3868

            // Initialize state from genesis.
            Self::set_params(ctx.runtime_state(), genesis.parameters);
            meta.versions.insert(Self::NAME.to_owned(), Self::VERSION);
            return true;
        }

        // Migrations are not supported.
        false
    }
}

impl module::AuthHandler for Module {}

impl module::BlockHandler for Module {}

impl module::InvariantHandler for Module {}
