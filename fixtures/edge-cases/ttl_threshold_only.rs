//! Edge-case fixture: TTL is maintained only through the
//! `extend_ttl_to_threshold` form, with no plain `extend_ttl` call in the
//! file. AP-STORAGE-001 explicitly accepts the threshold form, so the
//! expected findings are: none.
//!
//! This pins the threshold spelling as a first-class way to keep entries
//! alive, next to the plain form covered by fixtures/safe/ttl_managed.rs.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct ThresholdVault;

#[contractimpl]
impl ThresholdVault {
    /// Persistent write kept alive via the threshold extension form.
    pub fn store_balance(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        let storage = env.storage().persistent();
        storage.set(&key, &value);
        storage.extend_ttl_to_threshold(&key, 100);
    }

    /// Temporary write kept alive via the same threshold form.
    pub fn cache_quote(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        let storage = env.storage().temporary();
        storage.set(&key, &value);
        storage.extend_ttl_to_threshold(&key, 50);
    }

    /// Read of a threshold-maintained entry.
    pub fn read_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
