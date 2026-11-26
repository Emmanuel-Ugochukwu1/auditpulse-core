//! CI/SARIF fixture covering temporary and persistent storage without TTLs.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Session(Address),
    Balance(Address),
}

#[contract]
pub struct TtlStorageCiFixtures;

#[contractimpl]
impl TtlStorageCiFixtures {
    pub fn record_session(env: Env, owner: Address, nonce: u64) -> u64 {
        owner.require_auth();
        let key = DataKey::Session(owner);
        env.storage().temporary().set(&key, &nonce);
        nonce
    }

    pub fn persist_balance(env: Env, owner: Address, amount: i128) -> i128 {
        owner.require_auth();
        let key = DataKey::Balance(owner);
        // Deliberately omitted: both entries expire.
        env.storage().persistent().set(&key, &amount);
        amount
    }
}
