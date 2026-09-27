//! Safe fixture: every storage access is accompanied by an extend_ttl bump
//! and all writes stay admin-gated, so no rule may fire.
//!
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct LongLivedVault;

#[contractimpl]
impl LongLivedVault {
    pub fn load_balance(env: Env, user: Address) -> i128 {
        let balance = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        balance
    }

    pub fn save_balance(env: Env, admin: Address, user: Address, amount: i128) {
        admin.require_auth();
        env.storage().persistent().set(&user, &amount);
        env.storage().persistent().extend_ttl(&user, 100, 200);
    }

    pub fn store_marker(env: Env, admin: Address) {
        admin.require_auth();
        let key = Symbol::new(&env, "marker");
        env.storage().temporary().set(&key, &true);
        env.storage().temporary().extend_ttl(&key, 10, 20);
    }
}
