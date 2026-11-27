//! Static-analysis fixture for temporary and persistent storage TTL handling.
//!
//! The unchecked reads intentionally trigger AP-ERROR-001. AP-STORAGE-001 is
//! currently file-level: any recognized TTL extension suppresses it, even
//! across storage kinds, keys, functions, or branches. Silence from that rule
//! does not prove that every entry is kept alive on every execution path.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct StorageTtlEdgeCases;

#[contractimpl]
impl StorageTtlEdgeCases {
    /// An expired temporary entry can be absent; this read can panic.
    pub fn temporary_unchecked(env: Env, key: Symbol) -> u32 {
        env.storage().temporary().get(&key).unwrap()
    }

    /// An absent persistent entry also makes this unchecked read unsafe.
    pub fn persistent_unchecked(env: Env, key: Symbol) -> u32 {
        env.storage().persistent().get(&key).unwrap()
    }

    /// Only one branch extends the temporary entry's TTL.
    pub fn temporary_conditional(env: Env, key: Symbol, renew: bool) -> Option<u32> {
        let value = env.storage().temporary().get(&key);
        if renew && value.is_some() {
            env.storage().temporary().extend_ttl(&key, 100, 200);
        }
        value
    }

    /// An early return bypasses renewal of an existing persistent entry.
    pub fn persistent_early_return(env: Env, key: Symbol, renew: bool) -> Option<u32> {
        let value = env.storage().persistent().get(&key);
        if !renew {
            return value;
        }
        if value.is_some() {
            env.storage().persistent().extend_ttl(&key, 100, 200);
        }
        value
    }

    /// Extending a temporary entry does not renew the persistent entry.
    pub fn mixed_storage(env: Env, key: Address) -> Option<u32> {
        key.require_auth();
        env.storage().temporary().set(&key, &1u32);
        env.storage().temporary().extend_ttl(&key, 100, 200);
        env.storage().persistent().get(&key)
    }

    /// Both entries are written and renewed, using storage aliases.
    pub fn both_extended(env: Env, key: Address) {
        key.require_auth();
        let temporary = env.storage().temporary();
        let persistent = env.storage().persistent();
        temporary.set(&key, &1u32);
        persistent.set(&key, &1u32);
        temporary.extend_ttl(&key, 100, 200);
        persistent.extend_ttl(&key, 100, 200);
    }
}
