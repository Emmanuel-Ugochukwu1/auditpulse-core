//! Static-analysis fixture; archived persistent entries need restoration
//! before access. This file does not exercise a live Soroban ledger.
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct PersistentTtlEdgeCases;

#[contractimpl]
impl PersistentTtlEdgeCases {
    pub fn put(env: Env, owner: Address, key: Symbol, value: u32, refresh: bool) {
        owner.require_auth();
        let storage = env.storage().persistent();
        storage.set(&key, &value);
        if !refresh {
            return;
        }
        storage.extend_ttl(&key, 1, 2);
    }

    pub fn read_or_default(env: Env, key: Symbol) -> u32 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
