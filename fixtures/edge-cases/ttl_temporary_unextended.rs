//! Edge-case fixture: temporary storage is written and read, and no
//! `extend_ttl` call exists anywhere in the file.
//!
//! Expected findings: exactly one AP-STORAGE-001, reported at the first
//! storage access (`stash`). Temporary entries expire on the shortest
//! schedule, so an unextended temporary entry is the purest form of the
//! silent-expiry risk the rule exists to catch.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TemporaryOnly;

#[contractimpl]
impl TemporaryOnly {
    /// First storage access in the file: the AP-STORAGE-001 location.
    pub fn stash(env: Env, user: Address, value: u64) {
        user.require_auth();
        let key = Symbol::new(&env, "scratch");
        env.storage().temporary().set(&key, &value);
    }

    /// Temporary reads back as None once the entry has expired.
    pub fn recall(env: Env) -> u64 {
        let key = Symbol::new(&env, "scratch");
        env.storage().temporary().get(&key).unwrap_or(0)
    }
}
