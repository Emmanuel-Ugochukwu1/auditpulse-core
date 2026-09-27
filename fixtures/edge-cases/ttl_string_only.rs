//! Edge case: the only `storage().persistent()`-shaped text in the file sits
//! inside a string literal and there is no real storage access at all.
//! A string is not a ledger access, so the rule must stay silent.
//!
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct StringOnly;

#[contractimpl]
impl StringOnly {
    pub fn help(env: Env) -> Symbol {
        Symbol::new(&env, "read via env.storage().persistent() and default to zero")
    }
}
