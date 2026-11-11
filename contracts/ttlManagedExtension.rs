//! Clean demo: every storage access is paired with a TTL extension call.
//! Expected findings: none.
//!
//! Exercises the three extension APIs the scanner recognizes:
//!  * `env.storage().persistent().extend_ttl(&key, threshold, extend_to)`
//!  * `env.storage().temporary().extend_ttl_to_threshold(&key, threshold)`
//!  * `env.storage().instance().extend_ttl_to_threshold(&key, threshold)`
//! plus `get_extended`, which is also an accepted extension marker.
//!
//! The contract is clean in every other respect: every ledger write is
//! gated by `env.require_auth(&caller)`, no panicking calls, no unchecked
//! arithmetic on amount-like values, no cross-contract calls, no
//! admin/upgrade-shaped names, no debug macros.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlManagedStorage;

#[contractimpl]
impl TtlManagedStorage {
    /// Persistent storage extended with extend_ttl.
    pub fn save_persistent(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Temporary storage extended with extend_ttl_to_threshold.
    pub fn save_temporary(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().extend_ttl_to_threshold(&key, 50);
    }

    /// Instance storage extended with extend_ttl_to_threshold.
    pub fn save_instance(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().instance().set(&key, &value);
        env.storage().instance().extend_ttl_to_threshold(&key, 100);
    }

    /// A read that uses get_extended (also an accepted extension marker).
    pub fn load_persistent(env: Env, caller: Address, key: Symbol) -> i128 {
        env.require_auth(&caller);
        env.storage().persistent().get_extended(&key).unwrap_or_default()
    }

    /// Instance storage extended with the plain extend_ttl API.
    pub fn bump_instance(env: Env, caller: Address, key: Symbol) {
        env.require_auth(&caller);
        env.storage().instance().extend_ttl(&key, 100, 200);
    }
}