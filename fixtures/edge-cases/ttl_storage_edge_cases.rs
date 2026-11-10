//! Edge-case fixture: temporary vs. persistent storage TTL extensions.
//!
//! Expected findings:
//! - `no_ttl_anywhere` triggers AP-STORAGE-001 (storage access with no extend_ttl).
//! - `persistent_only_ttl` does NOT trigger AP-STORAGE-001 (extend_ttl is present).
//! - `temporary_storage_no_ttl` triggers AP-STORAGE-001 (temporary storage accessed, no extend_ttl).
//! - `mixed_ttl_and_no_ttl` does NOT trigger AP-STORAGE-001 (extend_ttl present somewhere).
//!
//! The rule is file-level: one finding when ANY storage access exists without
//! ANY extend_ttl in the file. So files with even one extend_ttl are clean.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TtlEdgeVault;

#[contractimpl]
impl TtlEdgeVault {
    /// Storage access with no extend_ttl anywhere in this function.
    pub fn no_ttl_anywhere(env: Env, key: Address, value: i128) {
        let mut entry = env.storage().persistent();
        entry.put(&key, &value);
    }

    /// Persistent storage with proper TTL extension.
    pub fn persistent_only_ttl(env: Env, key: Address, value: i128) {
        let mut entry = env.storage().persistent();
        entry.put(&key, &value);
        entry.extend_ttl(&key, 100, 200);
    }

    /// Temporary storage accessed without TTL (temporary entries expire faster).
    pub fn temporary_storage_no_ttl(env: Env, key: Address, value: i128) {
        let mut entry = env.storage().temporary();
        entry.put(&key, &value);
    }

    /// Mixed: one path has TTL, another does not. File-level rule sees the
    /// extend_ttl and stays silent.
    pub fn mixed_ttl_and_no_ttl(env: Env, key: Address, value: i128) {
        let mut entry = env.storage().persistent();
        entry.put(&key, &value);
        entry.extend_ttl(&key, 50, 100);

        // This second access has no TTL, but the file-level rule is satisfied
        // by the extend_ttl above.
        let mut entry2 = env.storage().temporary();
        entry2.put(&key, &value);
    }
}
