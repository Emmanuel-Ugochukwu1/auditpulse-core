//! Edge case: the storage access chain is formatted across several lines
//! (the style rustfmt produces for long expressions) and nothing is bumped.
//! The finding must still be reported, anchored to the `env.storage()` line
//! where the access begins.
//!
//! Expected findings: one AP-STORAGE-001.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct MultilineChain;

#[contractimpl]
impl MultilineChain {
    pub fn load(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "counter"))
            .unwrap_or(0)
    }
}
