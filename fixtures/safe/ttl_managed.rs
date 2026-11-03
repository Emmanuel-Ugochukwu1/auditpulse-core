//! Safe fixture: the same storage shapes as
//! fixtures/vulnerable/ttl_unmanaged.rs, but every tier's lifetime is
//! explicitly extended after the write. Expected findings: none.
//!
//! Kept in its own file on purpose: AP-STORAGE-001 is file-level, so the
//! managed and unmanaged shapes can only be tested in separate files.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct ManagedVault;

#[contractimpl]
impl ManagedVault {
    /// Persistent write followed by an explicit TTL bump for the entry.
    pub fn store_balance(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        let storage = env.storage().persistent();
        storage.set(&key, &value);
        storage.extend_ttl(&key, 100, 500);
    }

    /// Persistent read of an entry whose lifetime is maintained.
    pub fn read_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Temporary write with its short lifetime explicitly extended.
    pub fn cache_quote(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        let storage = env.storage().temporary();
        storage.set(&key, &value);
        storage.extend_ttl(&key, 50, 200);
    }

    /// Temporary read of a maintained entry.
    pub fn read_quote(env: Env, key: Symbol) -> i128 {
        env.storage().temporary().get(&key).unwrap_or(0)
    }

    /// Instance storage write with the instance lifetime extended.
    pub fn store_counter(env: Env, admin: Address, value: u32) {
        env.require_auth(&admin);
        let storage = env.storage().instance();
        storage.set(&KEY_COUNTER, &value);
        storage.extend_ttl(100, 500);
    }
}
