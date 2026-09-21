//! Sample Soroban smart contract demonstrating edge-case temporary vs. persistent
//! storage TTL extensions and unmanaged storage access for AuditPulse testing.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct TierConfig {
    pub threshold: u32,
    pub live: bool,
}

#[contract]
pub struct TtlStorageTiers;

#[contractimpl]
impl TtlStorageTiers {
    /// Vulnerable: writes persistent storage without extending TTL.
    pub fn set_persistent_unmanaged(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        env.storage().persistent().set(&key, &value);
    }

    /// Clean: persistent storage write with proper extend_ttl.
    pub fn set_persistent_managed(env: Env, admin: Address, key: Symbol, value: i128) {
        env.require_auth(&admin);
        let storage = env.storage().persistent();
        storage.set(&key, &value);
        storage.extend_ttl(&key, 100, 500);
    }

    /// Vulnerable: temporary storage write with unmanaged expiry and unsafe unwrap.
    pub fn get_temporary_edge(env: Env, key: Symbol) -> i128 {
        let temp = env.storage().temporary();
        temp.get(&key).unwrap()
    }

    /// Clean: temporary storage with explicit threshold extension and safe handling.
    pub fn extend_temporary_ttl(env: Env, admin: Address, key: Symbol, threshold: u32, extend_to: u32) {
        env.require_auth(&admin);
        let temp = env.storage().temporary();
        temp.extend_ttl(&key, threshold, extend_to);
    }
}
