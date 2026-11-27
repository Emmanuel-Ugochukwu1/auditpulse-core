//! Static-analysis fixture, not a ledger-expiration simulation.
//! Temporary values may be absent, so reads must tolerate a missing entry.
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TemporaryTtlEdgeCases;

#[contractimpl]
impl TemporaryTtlEdgeCases {
    pub fn put(env: Env, owner: Address, key: Symbol, value: u32, refresh: bool) {
        owner.require_auth();
        let storage = env.storage().temporary();
        storage.set(&key, &value);
        // Small nonzero thresholds exercise the near-expiration shape.
        if refresh {
            storage.extend_ttl(&key, 1, 2);
        }
    }

    pub fn read_or_default(env: Env, key: Symbol) -> u32 {
        env.storage().temporary().get(&key).unwrap_or(0)
    }
}
