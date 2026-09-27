//! Edge case: TTL extension through the threshold-based API
//! (`extend_ttl_to_threshold`) counts as a bump, and so does an explicit
//! `extend_ttl` on a different key than the one read. The rule is file-level
//! and accepts any of the documented extension calls.
//!
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct ThresholdTtl;

#[contractimpl]
impl ThresholdTtl {
    pub fn load_with_threshold(env: Env) -> u32 {
        let key = Symbol::new(&env, "counter");
        env.storage().persistent().extend_ttl_to_threshold(&key, 100);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn load_with_explicit_bump(env: Env) -> u32 {
        let counter = Symbol::new(&env, "counter");
        let marker = Symbol::new(&env, "marker");
        let value = env.storage().persistent().get(&counter).unwrap_or(0);
        env.storage().persistent().extend_ttl(&marker, 10, 20);
        value
    }
}
