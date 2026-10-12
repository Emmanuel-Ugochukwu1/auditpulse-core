//! Managed TTL counterpart for `TtlStorageTiers.rs` (#3).
//!
//! Persistent and temporary writes are followed by `extend_ttl`, and
//! mutations require auth — the scanner should stay quiet on AP-STORAGE-001.

#![allow(dead_code)]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageTiersManaged;

#[contractimpl]
impl TtlStorageTiersManaged {
    pub fn set_persistent_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = Symbol::new(&env, "bal_p");
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    pub fn set_temporary_scratch(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = Symbol::new(&env, "bal_t");
        env.storage().temporary().set(&key, &amount);
        env.storage().temporary().extend_ttl(&key, 50, 100);
    }

    pub fn read_tiers(env: Env) -> (Option<i128>, Option<i128>) {
        let pk = Symbol::new(&env, "bal_p");
        let tk = Symbol::new(&env, "bal_t");
        (
            env.storage().persistent().get(&pk),
            env.storage().temporary().get(&tk),
        )
    }
}
