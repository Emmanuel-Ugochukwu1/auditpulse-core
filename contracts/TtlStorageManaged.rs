//! TTL storage edge cases: the same storage surface, fully managed.
//!
//! Each storage access is paired with one of the extension forms the rule
//! recognises (`extend_ttl`, `extend_ttl_to_threshold`, `get_extended`), so
//! AP-STORAGE-001 must stay silent for this file.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Address),
}

#[contract]
pub struct TtlStorageManaged;

#[contractimpl]
impl TtlStorageManaged {
    pub fn persistent_balance(env: Env, owner: Address) -> i128 {
        let key = DataKey::Balance(owner);
        let value = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().extend_ttl(&key, 100, 200);
        value
    }

    pub fn temporary_nonce(env: Env, owner: Address) -> u64 {
        let key = DataKey::Nonce(owner);
        let value = env.storage().temporary().get(&key).unwrap_or(0);
        env.storage().temporary().extend_ttl_to_threshold(&key, 100);
        value
    }

    /// `get_extended` performs the read and the extension together.
    pub fn extended_balance(env: Env, owner: Address) -> i128 {
        let key = DataKey::Balance(owner);
        env.storage().persistent().get_extended(&key).unwrap_or(0)
    }
}
