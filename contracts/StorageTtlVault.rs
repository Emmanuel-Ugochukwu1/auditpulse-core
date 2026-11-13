//! Sample Soroban smart contract testing temporary vs. persistent storage
//! TTL extensions under edge-case logic for AuditPulse.
//!
//! Covers:
//! - Persistent storage entries extended with extend_ttl
//! - Temporary storage entries extended with extend_ttl_to_threshold
//! - Edge case: persistent storage access without extend_ttl (triggers AP-STORAGE-001)

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, Symbol,
};

#[contracttype]
pub enum StorageKey {
    PersistentData(Symbol),
    TemporarySession(Address),
    InstanceConfig,
}

#[contract]
pub struct StorageTtlVault;

#[contractimpl]
impl StorageTtlVault {
    /// Safe persistent storage access: properly bumped via extend_ttl.
    pub fn save_persistent(env: Env, from: Address, key: Symbol, value: i128) {
        env.require_auth(&from);
        let storage_key = StorageKey::PersistentData(key);
        env.storage().persistent().set(&storage_key, &value);
        // Extend TTL for persistent entry
        env.storage().persistent().extend_ttl(&storage_key, 1000, 5000);
    }

    /// Safe temporary storage access: properly bumped via extend_ttl_to_threshold.
    pub fn save_temporary_session(env: Env, user: Address, token: i128) {
        env.require_auth(&user);
        let session_key = StorageKey::TemporarySession(user);
        env.storage().temporary().set(&session_key, &token);
        // Extend temporary storage to threshold
        env.storage().temporary().extend_ttl_to_threshold(&session_key, 200, 1000);
    }

    /// Edge-case: reading instance storage and extending instance TTL.
    pub fn update_instance_config(env: Env, admin: Address) {
        env.require_auth(&admin);
        let _config: bool = env.storage().instance().get(&StorageKey::InstanceConfig).unwrap_or(false);
        env.storage().instance().extend_ttl(500, 2000);
    }
}
