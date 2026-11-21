//! Extension target is not matched to the access.
//!
//! `read_balance` reads a persistent balance, but the only extension in the
//! file bumps a temporary nonce for a different key. AP-STORAGE-001 checks
//! for the presence of an extension, not that it covers the accessed entry,
//! so this file is currently silent. This fixture documents that limitation
//! and keeps the current behaviour from changing accidentally.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Address),
}

#[contract]
pub struct TtlWrongKeyKind;

#[contractimpl]
impl TtlWrongKeyKind {
    pub fn read_balance(env: Env, owner: Address) -> i128 {
        let key = DataKey::Balance(owner.clone());
        let value = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .temporary()
            .extend_ttl(&DataKey::Nonce(owner), 100, 200);
        value
    }
}
