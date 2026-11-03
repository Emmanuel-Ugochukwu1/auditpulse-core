//! Vulnerable fixture: ledger storage used across all three tiers
//! (instance, persistent, temporary) with no TTL extension anywhere.
//! Expected findings: AP-STORAGE-001 exactly once, at file level, pointing
//! at the first storage access in `store_balance`.
//!
//! Every writer is auth-gated first and reads use `unwrap_or`, so the auth
//! and error-handling rules stay silent and the TTL finding is isolated.
//! The managed counterpart lives in fixtures/safe/ttl_managed.rs; the two
//! must stay in separate files because AP-STORAGE-001 is a file-level
//! rule: a single extension call anywhere in a file silences it for the
//! whole file, so mixing both shapes here would test nothing.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct UnmanagedVault;

#[contractimpl]
impl UnmanagedVault {
    /// Persistent write whose entry is left to expire on its own.
    pub fn store_balance(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        env.storage().persistent().set(&key, &value);
    }

    /// Persistent read of an entry whose lifetime nobody maintains.
    pub fn read_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Temporary write: the shortest-lived tier, still never extended.
    pub fn cache_quote(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        env.storage().temporary().set(&key, &value);
    }

    /// Temporary read of an entry that may silently read back as absent.
    pub fn read_quote(env: Env, key: Symbol) -> i128 {
        env.storage().temporary().get(&key).unwrap_or(0)
    }

    /// Instance storage write, also without any lifetime maintenance.
    pub fn store_counter(env: Env, admin: Address, value: u32) {
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_COUNTER, &value);
    }
}
