//! Sample Soroban smart contract exercising temporary vs. persistent storage
//! TTL edge cases, used as a scan target for AuditPulse.
//!
//! Every storage access below intentionally omits `extend_ttl`, so the
//! AP-STORAGE-001 rule fires once at file level, anchored at the first
//! storage access. Covered edge cases:
//! - persistent storage write with no TTL bump (entry can expire silently)
//! - persistent storage read with no TTL bump (reads don't extend TTL)
//! - temporary storage write/read with no TTL bump (temporary entries expire fastest)
//! - instance storage access with no TTL bump
//! - a commented-out extend_ttl (comments must not suppress the finding)

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Persistent write with no TTL bump: the entry can expire silently and
    /// later read back as `None`.
    pub fn save_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&user, &amount);
    }

    /// Persistent read with no TTL bump: reading an entry does not extend its
    /// live-until ledger, so hot keys still need explicit bumps.
    pub fn load_balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&user).unwrap_or(0)
    }

    /// Temporary storage write with no TTL bump: temporary entries carry the
    /// shortest default TTL on the network.
    pub fn cache_price(env: Env, symbol: Symbol, price: i128) {
        env.storage().temporary().set(&symbol, &price);
    }

    /// Temporary storage read with no TTL bump.
    pub fn read_cached_price(env: Env, symbol: Symbol) -> i128 {
        env.storage().temporary().get(&symbol).unwrap_or(0)
    }

    /// Instance storage access with no TTL bump.
    pub fn bump_calls(env: Env) -> u32 {
        let key = Symbol::new(&env, "calls");
        let calls: u32 = env.storage().instance().get(&key).unwrap_or(0);
        env.storage().instance().set(&key, &(calls + 1));
        calls + 1
    }

    // NOTE: a commented-out bump must NOT suppress the finding:
    // env.storage().persistent().extend_ttl(&user, 100, 200);
}
