//! Sample Soroban contract: temporary vs. persistent storage TTL edge cases.
//!
//! Intentionally vulnerable demo input for the AuditPulse scanner:
//! `npx ts-node src/index.ts contracts/TtlEdgeCases.rs`
//!
//! Exercises edge cases around ledger-entry lifetime:
//! - persistent entries written/read without any extend_ttl call,
//! - temporary entries relied on across invocations,
//! - an authorization-sensitive flush without require_auth,
//! - panicking reads via .unwrap() on possibly-expired entries.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Symbol};

#[contracttype]
pub enum TtlKey {
    /// Persistent per-user balance entry.
    Balance(Address),
    /// Temporary per-session allowance entry.
    SessionAllowance(Address),
    /// Persistent configuration entry.
    Config,
}

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Persistent write without extend_ttl: the balance can silently expire.
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&TtlKey::Balance(user), &amount);
    }

    /// Read of a possibly-expired persistent entry via .unwrap(): panics
    /// instead of handling the missing entry.
    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TtlKey::Balance(user))
            .unwrap()
    }

    /// Temporary storage written without extend_ttl: the allowance entry
    /// can expire between the approving call and the spending call.
    pub fn grant_session_allowance(env: Env, spender: Address, amount: i128) {
        env.storage()
            .temporary()
            .set(&TtlKey::SessionAllowance(spender), &amount);
    }

    /// Temporary storage read: returns 0 via unwrap_or after expiry, so a
    /// stale read silently downgrades the allowance.
    pub fn spend_session_allowance(env: Env, spender: Address, amount: i128) {
        let current: i128 = env
            .storage()
            .temporary()
            .get(&TtlKey::SessionAllowance(spender.clone()))
            .unwrap_or(0);
        let remaining = current - amount;
        env.storage()
            .temporary()
            .set(&TtlKey::SessionAllowance(spender), &remaining);
    }

    /// Authorization-sensitive flush of a balance to a token contract,
    /// missing require_auth.
    pub fn flush(env: Env, user: Address, token_id: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&user, &env.current_contract_address(), &amount);
        env.storage()
            .persistent()
            .set(&TtlKey::Balance(user), &0i128);
    }
}
