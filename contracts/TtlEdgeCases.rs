//! TTL edge-case fixture: temporary vs persistent storage extensions.
//!
//! AuditPulse's `AP-STORAGE-001` rule is file-level: it reports once when a
//! file touches `env.storage()` and calls none of `extend_ttl`,
//! `extend_ttl_to_threshold` or `get_extended` anywhere. This contract pins
//! that behaviour against the three ways a Soroban contract keeps ledger
//! entries alive:
//!
//! * `persistent().extend_ttl` for balances that must never expire,
//! * `temporary().extend_ttl_to_threshold` for caches that may expire,
//! * `get_extended` for reads that bump the entry as a side effect.
//!
//! It is deliberately clean apart from the TTL concern: authorization is
//! explicit and arithmetic is checked, so a scan of this file isolates the
//! storage rule instead of mixing it with unrelated findings.
//!
//! Scan target only: it is not compiled by this repository and holds no
//! real assets.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct Key {
    pub balances: Symbol,
    pub quotes: Symbol,
}

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Persistent entry, extended after every write. Balances must survive
    /// inactivity, so `extend_to` is far above the threshold.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);

        let key = Self::key(&env);
        let storage = env.storage().persistent();
        let current: i128 = storage.get(&key).unwrap_or(0);
        let next = match current.checked_add(amount) {
            Some(value) => value,
            None => return,
        };
        storage.set(&key, &next);

        // Threshold 100 ledgers, extend to 200: bumped on every write, and
        // alive for 200 ledgers of silence.
        storage.extend_ttl(&key, 100, 200);
    }

    /// Temporary entry kept alive with the threshold-based helper. A quote
    /// may expire; when it does, `get` returns `None` and the caller quotes
    /// again.
    pub fn quote(env: Env, caller: Address, id: u32) -> u32 {
        env.require_auth(&caller);

        let key = Self::quote_key(&env, id);
        let storage = env.storage().temporary();

        let next = match storage.get(&key) {
            Some(value) => match value.checked_add(1) {
                Some(bumped) => bumped,
                None => value,
            },
            None => 1,
        };
        storage.set(&key, &next);

        // No explicit extend_to: the runtime applies the default window once
        // the remaining TTL drops below the threshold.
        storage.extend_ttl_to_threshold(&key, 50);
        next
    }

    /// Read that also bumps the entry, for callers that never write.
    pub fn peek(env: Env, user: Address) -> Option<i128> {
        let key = Self::key(&env);
        env.storage().persistent().get_extended(&key)
    }

    /// Instance storage is extended by threshold, without a key.
    pub fn bump_instance(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
    }

    /// Reads the raw instance value without extending it; the instance entry
    /// is kept alive by `bump_instance`, which this fixture calls separately.
    pub fn last_seen(env: Env) -> u32 {
        env.storage().instance().get(&Self::key(&env)).unwrap_or(0)
    }

    fn key(env: &Env) -> Symbol {
        Symbol::new(env, "balances")
    }

    fn quote_key(env: &Env, id: u32) -> (Symbol, u32) {
        (Symbol::new(env, "quotes"), id)
    }
}
