//! TTL storage-tier fixture: persistent, temporary, and instance entries
//! written or read with no `extend_ttl`, plus an expired-read edge case.
//!
//! Every writer below is `require_auth`-gated and performs no token
//! movement, arithmetic, or admin reconfiguration, so the only expected
//! findings are AP-STORAGE-001 (missing TTL extension) and AP-ERROR-001
//! (`.unwrap()` on a read that returns `None` once the entry expires).
//! Scan it with: `node dist/index.js scan contracts/TtlStorageTiers.rs`

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageTiers;

#[contractimpl]
impl TtlStorageTiers {
    /// Persistent tier with no TTL extension: the entry silently expires.
    pub fn save_balance(env: Env, user: Address, value: i128) {
        env.require_auth(&user);
        env.storage().persistent().set(&user, &value);
    }

    /// Temporary tier with no TTL extension: short-lived entries vanish first.
    pub fn save_session(env: Env, user: Address, token: Symbol) {
        env.require_auth(&user);
        env.storage().temporary().set(&user, &token);
    }

    /// Instance tier with no TTL extension: contract-level state expires too.
    pub fn save_threshold(env: Env, admin: Address, threshold: u32) {
        env.require_auth(&admin);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "threshold"), &threshold);
    }

    /// Edge case: reading a possibly-expired entry with `.unwrap()`.
    /// After TTL expiry the `get` returns `None` and the contract panics.
    pub fn load_balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&user).unwrap()
    }
}
