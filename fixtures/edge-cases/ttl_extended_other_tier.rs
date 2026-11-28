//! Edge-case fixture: only the persistent entry is extended; the
//! temporary entry in the same file is not.
//!
//! Expected findings: none. AP-STORAGE-001 is a file-level rule: a single
//! `extend_ttl` call anywhere in the file silences it, even when the call
//! covers a different storage tier (and a different key) than the entry
//! left to expire. This fixture pins that masking behaviour so a future
//! per-tier / per-key version of the rule has a failing test to aim at.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct MixedTierTtl;

#[contractimpl]
impl MixedTierTtl {
    /// Persistent entry, extended in the same function.
    pub fn save_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = Symbol::new(&env, "balance");
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Temporary entry, never extended: masked by save_balance's call.
    pub fn cache_quote(env: Env, user: Address, quote: i128) {
        user.require_auth();
        let key = Symbol::new(&env, "quote");
        env.storage().temporary().set(&key, &quote);
    }
}
