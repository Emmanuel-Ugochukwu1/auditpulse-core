//! Sample Soroban smart contract demonstrating storage TTL tiers and edge cases.
//!
//! This contract illustrates persistent and temporary storage writes and reads
//! where entries are not accompanied by extend_ttl, triggering AP-STORAGE-001.

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

#[contract]
pub struct TtlStorageTiers;

#[contractimpl]
impl TtlStorageTiers {
    /// Writes user balance to persistent storage without extending TTL.
    /// Triggers AP-STORAGE-001.
    pub fn save_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::UserBalance(user);
        env.storage().persistent().set(&key, &amount);
    }

    /// Reads user balance from persistent storage.
    pub fn get_balance(env: Env, user: Address) -> Option<i128> {
        let key = DataKey::UserBalance(user);
        env.storage().persistent().get(&key)
    }

    /// Saves session nonce in temporary storage without extending TTL.
    pub fn save_session(env: Env, user: Address, nonce: u64) {
        user.require_auth();
        let key = DataKey::SessionNonce(user);
        env.storage().temporary().set(&key, &nonce);
    }

    /// Reads session nonce from temporary storage.
    pub fn get_session(env: Env, user: Address) -> Option<u64> {
        let key = DataKey::SessionNonce(user);
        env.storage().temporary().get(&key)
    }
}
