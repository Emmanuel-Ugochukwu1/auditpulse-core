//! Sample Soroban smart contract demonstrating edge-case storage expirations
//! and TTL extension handling across temporary, persistent, and instance tiers.
//!
//! Scenarios:
//! 1. Persistent ledger storage: user balances with explicit extend_ttl (safe)
//! 2. Temporary storage: ephemeral nonce/session tracking with extend_ttl_to_threshold (safe)
//! 3. Instance storage maintenance: bumping instance TTL (safe)

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, Symbol,
};

#[contracttype]
pub enum ExpiryKey {
    UserBalance(Address),
    SessionNonce(Address),
    ContractConfig,
}

#[contract]
pub struct StorageExpiryVault;

#[contractimpl]
impl StorageExpiryVault {
    /// Safe persistent balance update: extends persistent TTL.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.require_auth(&from);
        let key = ExpiryKey::UserBalance(from.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_add(amount).unwrap_or(balance);
        env.storage().persistent().set(&key, &new_balance);

        // Bump persistent storage TTL to avoid silent data archiving
        env.storage().persistent().extend_ttl(&key, 1000, 10000);
    }

    /// Safe temporary session tracker: ephemeral state with extend_ttl_to_threshold.
    pub fn record_action(env: Env, user: Address, nonce: u64) {
        env.require_auth(&user);
        let session_key = ExpiryKey::SessionNonce(user.clone());
        env.storage().temporary().set(&session_key, &nonce);

        // Ephemeral temporary entries must be extended to threshold
        env.storage().temporary().extend_ttl_to_threshold(&session_key, 100, 500);
    }

    /// Safe instance storage maintenance: bumps contract instance TTL.
    pub fn maintain_instance(env: Env, admin: Address) {
        env.require_auth(&admin);
        let _active: bool = env.storage().instance().get(&ExpiryKey::ContractConfig).unwrap_or(true);
        env.storage().instance().extend_ttl(500, 3000);
    }
}
