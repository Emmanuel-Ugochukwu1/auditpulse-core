//! Vulnerable fixture: persistent and temporary ledger entries are read and
//! written without any extend_ttl bump, so entries that were never extended
//! silently read back as None once they expire.
//!
//! Expected findings: exactly one file-level AP-STORAGE-001, anchored to the
//! first storage access inside `load_balance`.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct ExpiringVault;

#[contractimpl]
impl ExpiringVault {
    pub fn load_balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&user).unwrap_or(0)
    }

    pub fn save_balance(env: Env, admin: Address, user: Address, amount: i128) {
        admin.require_auth();
        env.storage().persistent().set(&user, &amount);
        env.storage().temporary().set(&Symbol::new(&env, "last"), &amount);
    }

    pub fn read_marker(env: Env) -> Symbol {
        env.storage()
            .temporary()
            .get(&Symbol::new(&env, "last"))
            .unwrap_or(Symbol::new(&env, "none"))
    }
}
