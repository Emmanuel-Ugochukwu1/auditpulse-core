//! Sample Soroban smart contract for testing temporary vs persistent storage TTL edge cases.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct TtlStorageEdgeCase;

#[contractimpl]
impl TtlStorageEdgeCase {
    /// Tests temporary vs persistent storage TTL extension edge cases.
    pub fn test_ttls(env: Env) {
        let key = Symbol::new(&env, "edge_key");
        let val = 500u32;

        // Temporary storage TTL extension
        env.storage().temporary().set(&key, &val);
        env.storage().temporary().extend_ttl(&key, 1000, 5000);

        // Persistent storage TTL extension
        env.storage().persistent().set(&key, &val);
        env.storage().persistent().extend_ttl(&key, 2000, 10000);

        // Instance storage TTL extension
        env.storage().instance().extend_ttl(500, 2500);
    }
}
