//! Edge-case contract: temporary vs. persistent storage TTL extensions.
//!
//! Tests the scanner's AP-STORAGE-001 rule across storage lifetimes:
//!   - `temp_with_ttl`      — temporary entry, extend_ttl present (silent)
//!   - `persistent_with_ttl`— persistent entry, extend_ttl present (silent)
//!   - `temp_missing_ttl`   — temporary entry, no extend_ttl (flagged)
//!   - `persistent_missing` — persistent entry, no extend_ttl (flagged)
//!   - `mixed_lifetimes`    — one entry extended, one not (partial flag)
//!   - `zero_threshold_ttl` — extend_ttl called with 0 threshold (edge)
//!
//! Expected AP-STORAGE-001 findings: temp_missing_ttl, persistent_missing,
//! and mixed_lifetimes (for the unextended entry). zero_threshold_ttl calls
//! extend_ttl and must stay silent — the rule checks for the call, not the
//! argument value.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Symbol};

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Temporary storage with extend_ttl: correctly kept alive.
    pub fn temp_with_ttl(env: Env, key: Symbol, value: Address) {
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().extend_ttl(&key, 100, 200);
    }

    /// Persistent storage with extend_ttl: correctly kept alive.
    pub fn persistent_with_ttl(env: Env, key: Symbol, value: Address) {
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Temporary storage WITHOUT extend_ttl: entry may expire prematurely.
    pub fn temp_missing_ttl(env: Env, key: Symbol, value: Address) {
        env.storage().temporary().set(&key, &value);
    }

    /// Persistent storage WITHOUT extend_ttl: entry may be archived.
    pub fn persistent_missing(env: Env, key: Symbol, value: Address) {
        env.storage().persistent().set(&key, &value);
    }

    /// Mixed lifetimes: temporary entry extended, persistent entry not.
    /// The persistent entry is the one at risk.
    pub fn mixed_lifetimes(env: Env, t_key: Symbol, p_key: Symbol, value: Address) {
        env.storage().temporary().set(&t_key, &value);
        env.storage().temporary().extend_ttl(&t_key, 50, 100);
        env.storage().persistent().set(&p_key, &value);
    }

    /// extend_ttl called with a zero threshold: unusual but the call exists.
    /// The scanner checks for the presence of extend_ttl, not its arguments.
    pub fn zero_threshold_ttl(env: Env, key: Symbol, value: Address) {
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().extend_ttl(&key, 0, 0);
    }

    /// Read-only temporary access without extend_ttl: reads do not need
    /// TTL extension — only writes create entries that can expire.
    pub fn temp_read_only(env: Env, key: Symbol) -> Option<Address> {
        env.storage().temporary().get(&key)
    }
}
