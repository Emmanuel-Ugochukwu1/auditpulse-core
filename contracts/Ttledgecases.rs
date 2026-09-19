//! Sample Soroban contract exercising temporary vs. persistent storage TTL
//! edge cases for AuditPulse rule AP-STORAGE-001 (missing `extend_ttl`).
//!
//! The contract reads and writes BOTH temporary and persistent ledger entries
//! but never actually bumps either TTL. Every mention of `extend_ttl` below is
//! inside a comment, so the scanner must ignore it and report exactly one
//! file-level finding at the first storage access (`set_session`):
//!
//!   npx tsx src/index.ts contracts/TtlEdgeCases.rs
//!
//! Temporary entries are cheap and expected to expire, but a session that
//! silently vanishes mid-flow is still a bug; persistent entries such as
//! balances must never expire unnoticed.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Session(Address),
    Balance(Address),
}

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Temporary storage: short-lived login session.
    pub fn set_session(env: Env, user: Address, nonce: u64) {
        env.require_auth(&user);
        env.storage().temporary().set(&DataKey::Session(user), &nonce);
        // env.storage().temporary().extend_ttl(&key, 10, 20);  <- commented out
    }

    /// Temporary storage read with no bump: the entry may already be gone.
    pub fn get_session(env: Env, user: Address) -> Option<u64> {
        env.storage().temporary().get(&DataKey::Session(user))
    }

    /// Persistent storage: long-lived balance that must survive expiry.
    pub fn record_balance(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);
        env.storage().persistent().set(&DataKey::Balance(user), &amount);
        /* env.storage().persistent().extend_ttl(&key, 100, 200);
           also commented out, in a block comment */
    }

    /// Persistent storage read with no bump.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(user)).unwrap_or(0)
    }

    /// Not storage related; keeps `Symbol` import meaningful.
    pub fn version(env: Env) -> Symbol {
        Symbol::new(&env, "v1")
    }
}