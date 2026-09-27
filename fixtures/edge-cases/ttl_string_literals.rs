//! Edge case: a `.extend_ttl(` mention appears only inside a string literal
//! (the kind of usage hint that ends up in user-facing messages), while the
//! real storage read is never bumped. String text is not executable code:
//! it must neither satisfy the file-level bump check nor move the anchor
//! away from the real access.
//!
//! Expected findings: one AP-STORAGE-001, anchored to the line of the real
//! `env.storage()` access — not to the string.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct LiteralTtl;

#[contractimpl]
impl LiteralTtl {
    pub fn load(env: Env) -> u32 {
        let hint = "remember to call env.storage().persistent().extend_ttl(&key, 100, 200)";
        let _ = hint;
        let key = Symbol::new(&env, "counter");
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
