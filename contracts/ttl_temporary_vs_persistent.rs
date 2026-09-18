//! Issue #3 — Edge-case TTL / storage expirations: temporary vs. persistent
//! instance storage read together without any TTL bump.
//!
//! Both `temporary()` and `persistent()` ledger entries are subject to time-based
//! expiry (and, for temporary entries, absolute live-until semantics). If a
//! contract reads and trusts those entries without ever calling
//! `extend_ttl` / `extend_ttl_to_threshold` / `get_extended`, the values can
//! silently read back as `None` after expiry.
//!
//! This fixture triggers `AP-STORAGE-001` (Missing Extend TTL): it touches both
//! storage tiers and performs no TTL maintenance anywhere in the file.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum Key {
    Balance(Address),
    Nonce,
    Temp(Address),
}

#[contract]
pub struct TtlVault;

#[contractimpl]
impl TtlVault {
    /// Uses BOTH persistent and temporary storage, and bumps neither.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        let mut balance: i128 = env.storage().persistent().get(&Key::Balance(user)).unwrap_or(0);
        balance = balance + amount;
        env.storage().persistent().set(&Key::Balance(user), &balance);
    }

    /// Reads the temporary/live lease before acting on it.
    pub fn live_lease_left(env: Env, user: Address) -> u32 {
        env.storage()
            .temporary()
            .get(&Key::Temp(user))
            .unwrap_or(0)
    }

    /// Plain instance counter — also never extended.
    pub fn nonce(env: Env) -> u32 {
        env.storage().instance().get(&Key::Nonce).unwrap_or(0)
    }
}
