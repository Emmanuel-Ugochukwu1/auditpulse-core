//! Issue #2 — Detection across complex Soroban macro expansions.
//!
//! Real Soroban contracts often delegate TTL maintenance to shared helpers and
//! access storage through `soroban_sdk::contractimpl`-generated code and
//! `#[macro_use]`-style helper macros. The Missing-Extend-TTL rule must still
//! "see through" that expansion: a file that correctly bumps a persistent entry
//! via `extend_ttl_to_threshold` (a valid bump) must NOT be flagged, even when
//! the storage touch itself lives inside macro-heavy code.
//!
//! This fixture is intentionally SAFE: it performs a TTL bump, so the scanner
//! must report no `AP-STORAGE-001`.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct DataKey {
    pub key: Symbol,
}

/// Macro-style helper that both reads the entry and extends its TTL in one step.
macro_rules! read_with_bump {
    ($env:expr, $key:expr) => {{
        let val = $env.storage().instance().get::<DataKey>(&$key);
        // Bump to threshold so the stored entry never silently expires.
        $env.storage()
            .instance()
            .extend_ttl_to_threshold(&$key);
        val
    }};
}

#[contract]
pub struct MacroVault;

#[contractimpl]
impl MacroVault {
    /// Uses the macro helper which bumps TTL — must NOT be flagged.
    pub fn get_config(env: Env) -> Option<DataKey> {
        let key = DataKey { key: Symbol::new(&env, "cfg") };
        macro_rules! local_read {
            () => {
                read_with_bump!(&env, &key)
            };
        }
        local_read!()
    }

    /// Explicit, inlined persistent read that is also bumped — safe.
    pub fn write_config(env: Env, cfg: DataKey) {
        env.storage().persistent().set(&cfg, &cfg);
        env.storage()
            .persistent()
            .extend_ttl_to_threshold(&cfg);
    }
}
