//! Edge case: only instance storage is touched (no persistent or temporary
//! access) and nothing is bumped. The rule's current scope covers instance
//! access too, so this fixture pins that behaviour explicitly — the README
//! summary only mentions persistent/temporary entries, and any scope
//! narrowing must be a deliberate, tested change.
//!
//! Expected findings: one AP-STORAGE-001.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct InstanceOnly;

#[contractimpl]
impl InstanceOnly {
    pub fn counter(env: Env) -> u32 {
        env.storage().instance().get(&Symbol::new(&env, "counter")).unwrap_or(0)
    }
}
