//! Issue #1 — Edge-case TTL / storage expiration for CI/SARIF scan targets.
//!
//! A minimal, single-tier contract that persistently stores a user balance and
//! reads it back in a withdrawal path WITHOUT ever extending the entry's TTL.
//! This is the canonical "persistent entry expires and reads back as None" case
//! that CI pipelines (via JSON / SARIF output) should flag as `AP-STORAGE-001`.
//!
//! This fixture is INTENTIONALLY VULNERABLE: it performs no
//! `extend_ttl` / `extend_ttl_to_threshold` / `get_extended`, so the scanner
//! must report one `AP-STORAGE-001`.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Key {
    Balance(Address),
}

#[contract]
pub struct Role;

#[contractimpl]
impl Role {
    /// Reads a persistent balance and withdraws — entry is never TTL-extended.
    pub fn withdraw_partial(env: Env, user: Address, amount: i128) -> i128 {
        let mut balance: i128 = env.storage().persistent().get(&Key::Balance(user)).unwrap_or(0);
        if balance >= amount {
            balance = balance - amount;
        }
        env.storage().persistent().set(&Key::Balance(user), &balance);
        balance
    }
}
