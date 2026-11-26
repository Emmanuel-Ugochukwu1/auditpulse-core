//! Mixed storage tiers for AP-STORAGE-001 coverage.
//!
//! The temporary session is extended, but the persistent balance is not.
//! A TTL extension for one entry must not hide the uncovered entry.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Session(Address),
    Balance(Address),
}

#[contract]
pub struct TtlStorageCoverage;

#[contractimpl]
impl TtlStorageCoverage {
    pub fn record_session(env: Env, owner: Address, nonce: u64) -> u64 {
        owner.require_auth();
        let key = DataKey::Session(owner);
        env.storage().temporary().set(&key, &nonce);
        env.storage().temporary().extend_ttl(&key, 100, 200);
        nonce
    }

    pub fn persist_balance(env: Env, owner: Address, amount: i128) -> i128 {
        owner.require_auth();
        let key = DataKey::Balance(owner);
        // Deliberately uncovered: the round-trip expires with this entry.
        env.storage().persistent().set(&key, &amount);
        amount
    }
}
