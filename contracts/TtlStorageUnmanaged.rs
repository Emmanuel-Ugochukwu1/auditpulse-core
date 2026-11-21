//! TTL storage edge cases: unmanaged persistent and temporary entries.
//!
//! Every function below reads or writes ledger storage without calling
//! `extend_ttl`. The AP-STORAGE-001 rule is file-level, so this file is kept
//! separate from the managed fixture: an extension in another function must
//! not mask the first unmanaged access here.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Address),
    Paused,
}

#[contract]
pub struct TtlStorageUnmanaged;

#[contractimpl]
impl TtlStorageUnmanaged {
    /// First storage access in the file: persistent read without a bump.
    pub fn persistent_balance(env: Env, owner: Address) -> i128 {
        let key = DataKey::Balance(owner);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn set_persistent_balance(env: Env, owner: Address, amount: i128) {
        let key = DataKey::Balance(owner);
        env.storage().persistent().set(&key, &amount);
    }

    /// Temporary entries expire even faster than persistent ones, yet this
    /// access is also left unmanaged.
    pub fn temporary_nonce(env: Env, owner: Address) -> u64 {
        let key = DataKey::Nonce(owner);
        env.storage().temporary().get(&key).unwrap_or(0)
    }

    pub fn set_temporary_nonce(env: Env, owner: Address, nonce: u64) {
        let key = DataKey::Nonce(owner);
        env.storage().temporary().set(&key, &nonce);
    }

    /// Presence guards do not keep an entry alive: `has` can return true and
    /// the following `get` can still race an expiry.
    pub fn presence_guarded(env: Env) -> bool {
        if env.storage().persistent().has(&DataKey::Paused) {
            env.storage().persistent().get(&DataKey::Paused).unwrap()
        } else {
            false
        }
    }
}
