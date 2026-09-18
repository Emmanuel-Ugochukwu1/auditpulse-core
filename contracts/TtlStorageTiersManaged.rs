//! Sample Soroban smart contract demonstrating managed storage TTL extensions.
//!
//! This contract illustrates persistent and temporary storage writes and reads
//! accompanied by extend_ttl and extend_ttl_to_threshold, resolving AP-STORAGE-001.

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, Symbol,
};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    UserBalance(Address),
    SessionNonce(Address),
    AdminConfig,
}

const PERSISTENT_BUMP_THRESHOLD: u32 = 17280; // ~1 day in ledgers (5s/ledger)
const PERSISTENT_LIFETIME: u32 = 518400;      // ~30 days in ledgers
const TEMPORARY_BUMP_THRESHOLD: u32 = 1000;
const TEMPORARY_LIFETIME: u32 = 10000;

#[contract]
pub struct TtlStorageTiersManaged;

#[contractimpl]
impl TtlStorageTiersManaged {
    /// Writes user balance and extends persistent storage TTL.
    pub fn save_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::UserBalance(user);
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_LIFETIME);
    }

    /// Reads user balance and bumps persistent TTL.
    pub fn get_balance(env: Env, user: Address) -> Option<i128> {
        let key = DataKey::UserBalance(user);
        let balance = env.storage().persistent().get(&key);
        if balance.is_some() {
            env.storage().persistent().extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_LIFETIME);
        }
        balance
    }

    /// Saves session nonce and extends temporary storage TTL.
    pub fn save_session(env: Env, user: Address, nonce: u64) {
        user.require_auth();
        let key = DataKey::SessionNonce(user);
        env.storage().temporary().set(&key, &nonce);
        env.storage().temporary().extend_ttl(&key, TEMPORARY_BUMP_THRESHOLD, TEMPORARY_LIFETIME);
    }

    /// Reads session nonce using extend_ttl_to_threshold helper.
    pub fn get_session(env: Env, user: Address) -> Option<u64> {
        let key = DataKey::SessionNonce(user);
        let nonce = env.storage().temporary().get(&key);
        if nonce.is_some() {
            env.storage().temporary().extend_ttl_to_threshold(&key, TEMPORARY_BUMP_THRESHOLD, TEMPORARY_LIFETIME);
        }
        nonce
    }
}
