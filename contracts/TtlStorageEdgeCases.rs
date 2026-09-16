//! Edge-case fixture for temporary and persistent Soroban storage expiry.
//! Intentionally unsafe scanner input; not production contract code.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum StorageKey {
    Balance(Address),
    Session(Address),
}

#[contract]
pub struct TtlStorageEdgeCases;

#[contractimpl]
impl TtlStorageEdgeCases {
    pub fn remember_balance(env: Env, owner: Address, amount: i128) {
        env.require_auth(&owner);
        env.storage()
            .persistent()
            .set(&StorageKey::Balance(owner), &amount);
    }

    pub fn remember_session(env: Env, owner: Address, value: i128) {
        env.require_auth(&owner);
        env.storage()
            .temporary()
            .set(&StorageKey::Session(owner), &value);
    }

    pub fn balance(env: Env, owner: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&StorageKey::Balance(owner))
            .unwrap()
    }
}
