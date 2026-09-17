//! Sample Soroban smart contract demonstrating edge-case TTL and storage expirations.
//!
//! This contract intentionally contains vulnerable patterns around ledger-entry lifetimes:
//! 1. Persistent storage entries written and read without `extend_ttl` (risking archival).
//! 2. Temporary storage entries relied upon without `extend_ttl` (risking permanent deletion).
//! 3. Fallible reads on potentially expired entries using `.unwrap()` (leading to contract panic).
//! 4. Unprotected state mutation without `require_auth`.
//!
//! Used as a scan target for AuditPulse:
//! `npx tsx src/index.ts contracts/StorageTtlEdgeCases.rs`

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Symbol};

#[contracttype]
pub enum StorageKey {
    /// Persistent user balance entry.
    Balance(Address),
    /// Temporary session allowance entry (ephemeral lease).
    SessionAllowance(Address),
    /// Contract instance configuration.
    Config,
}

#[contract]
pub struct StorageTtlEdgeCases;

#[contractimpl]
impl StorageTtlEdgeCases {
    /// Edge Case 1: Persistent write without extend_ttl.
    /// The ledger entry can silently expire and get archived.
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&StorageKey::Balance(user), &amount);
    }

    /// Edge Case 2: Reading a possibly-expired persistent entry using .unwrap().
    /// If the entry has expired/archived, get() returns None, causing a panic.
    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&StorageKey::Balance(user)).unwrap()
    }

    /// Edge Case 3: Temporary storage written without extending TTL.
    /// Temporary entries are deleted upon expiry and cannot be restored.
    pub fn grant_session(env: Env, user: Address, allowance: i128) {
        env.storage().temporary().set(&StorageKey::SessionAllowance(user), &allowance);
    }

    /// Edge Case 4: Temporary storage read with fallback after silent expiry.
    /// When temporary storage expires, unwrap_or(0) causes silent state reset.
    pub fn consume_session(env: Env, user: Address, amount: i128) -> i128 {
        let current: i128 = env.storage().temporary().get(&StorageKey::SessionAllowance(user.clone())).unwrap_or(0);
        let updated = current - amount;
        env.storage().temporary().set(&StorageKey::SessionAllowance(user), &updated);
        updated
    }

    /// Edge Case 5: Unauthorized state mutation and token transfer.
    pub fn emergency_drain(env: Env, user: Address, token_id: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&user, &env.current_contract_address(), &amount);
        env.storage().persistent().set(&StorageKey::Balance(user), &0i128);
    }
}
