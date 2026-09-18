//! Managed counterpart to `TtlStorageTiers.rs`: the same persistent,
//! temporary, and instance storage tiers, but every entry is kept alive
//! with a TTL extension and errors propagate via `Result`.
//!
//! Expected scan result: zero findings.
//! Scan it with: `node dist/index.js scan contracts/TtlStorageTiersManaged.rs`

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageTiersManaged;

#[contractimpl]
impl TtlStorageTiersManaged {
    /// Persistent tier with a standard TTL bump after every write.
    pub fn save_balance(env: Env, user: Address, value: i128) {
        env.require_auth(&user);
        env.storage().persistent().set(&user, &value);
        env.storage().persistent().extend_ttl(&user, 100, 200);
    }

    /// Temporary tier with a TTL bump after every write.
    pub fn save_session(env: Env, user: Address, token: Symbol) {
        env.require_auth(&user);
        env.storage().temporary().set(&user, &token);
        env.storage().temporary().extend_ttl(&user, 50, 100);
    }

    /// Instance tier kept alive via the threshold-based extension API.
    pub fn save_threshold(env: Env, admin: Address, threshold: u32) {
        env.require_auth(&admin);
        let key = Symbol::new(&env, "threshold");
        env.storage().instance().set(&key, &threshold);
        env.storage().instance().extend_ttl_to_threshold(&key, 200);
    }

    /// Expired entries surface as `None` and propagate as an error,
    /// never as a panic.
    pub fn load_balance(env: Env, user: Address) -> Result<i128, Error> {
        env.storage()
            .persistent()
            .get(&user)
            .ok_or(Error::BalanceNotSet)
    }
}

pub enum Error {
    BalanceNotSet,
}
