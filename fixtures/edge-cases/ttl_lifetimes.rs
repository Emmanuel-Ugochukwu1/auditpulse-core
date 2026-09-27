//! Edge case: lifetime parameters (`&'a`, `<'a>`) must not disturb the
//! comment/string blanking or move the storage anchor, and a missing bump
//! must still be reported in lifetime-heavy signatures.
//!
//! Expected findings: one AP-STORAGE-001, anchored to the real access inside
//! `read_with`.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct LifetimeTtl;

#[contractimpl]
impl LifetimeTtl {
    pub fn read_with<'a>(env: Env, key: &'a Symbol) -> u32 {
        let borrowed: &'a Symbol = key;
        let _ = &borrowed;
        env.storage().persistent().get(borrowed).unwrap_or(0)
    }

    pub fn describe<'a>(env: Env, label: &'a str) -> Symbol {
        let _ = label;
        Symbol::new(&env, "label")
    }
}
