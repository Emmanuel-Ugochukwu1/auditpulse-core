//! Edge case: the only extend_ttl mentions live in comments. Commented-out
//! code is not an implemented bump, so the file-level check must still fire.
//!
//! Expected findings: one AP-STORAGE-001.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct CommentedTtl;

#[contractimpl]
impl CommentedTtl {
    pub fn load(env: Env) -> u32 {
        // env.storage().persistent().extend_ttl(&key, 100, 200);
        let key = Symbol::new(&env, "counter");
        /* env.storage().temporary().extend_ttl(&key, 10, 20); */
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
