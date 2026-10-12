//! TTL / storage-expiration edge-case fixture for AuditPulse (#3).
//!
//! Demonstrates temporary vs persistent ledger entries that are written
//! without any TTL bump helper. On Soroban, both kinds can expire and later
//! read back as `None` — this sample is the unmanaged (vulnerable) side of
//! the temporary/persistent TTL matrix.
//!
//! Pair with `contracts/TtlStorageTiersManaged.rs` for the managed counterpart.
//! Scan target: `npx auditpulse scan contracts/TtlStorageTiers.rs`

#![allow(dead_code)]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageTiers;

#[contractimpl]
impl TtlStorageTiers {
    /// Writes a **persistent** balance with no TTL extension.
    pub fn set_persistent_balance(env: Env, user: Address, amount: i128) {
        let key = Symbol::new(&env, "bal_p");
        env.storage().persistent().set(&key, &amount);
        // Intentionally unmanaged: no TTL bump after the persistent write.
        let _ = user;
    }

    /// Writes a **temporary** scratch value with no TTL extension.
    pub fn set_temporary_scratch(env: Env, user: Address, amount: i128) {
        let key = Symbol::new(&env, "bal_t");
        env.storage().temporary().set(&key, &amount);
        // Intentionally unmanaged: no TTL bump after the temporary write.
        let _ = user;
    }

    /// Reads both tiers after a hypothetical expiry window — values may be None.
    pub fn read_tiers(env: Env) -> (Option<i128>, Option<i128>) {
        let pk = Symbol::new(&env, "bal_p");
        let tk = Symbol::new(&env, "bal_t");
        let persistent = env.storage().persistent().get(&pk);
        let temporary = env.storage().temporary().get(&tk);
        (persistent, temporary)
    }
}
