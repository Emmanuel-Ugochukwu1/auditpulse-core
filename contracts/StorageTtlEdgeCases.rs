//! Sample Soroban contract for edge-case TTL / storage-expiration testing
//! (GitHub issue #3). Scan target for `tests/storageTtlEdgeCases.test.ts`.
//!
//! The contract deliberately mixes storage tiers and extension styles:
//!
//! - `save_profile` writes **persistent** storage and extends that entry's
//!   TTL in the same function: the well-behaved pattern.
//! - `open_session` writes **temporary** storage and never extends it.
//!   Temporary entries expire fastest, so this is the entry most at risk —
//!   yet AP-STORAGE-001 stays silent for the whole file because the rule is
//!   file-level and an `extend_ttl` call exists elsewhere. The unit test
//!   pins that masking behaviour as a documented edge case.
//! - `touch_instance` extends the **instance** TTL, whose `extend_ttl`
//!   takes `(threshold, extend_to)` with no key argument, unlike the
//!   persistent/temporary form.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct StorageTtlEdgeCases;

#[contractimpl]
impl StorageTtlEdgeCases {
    /// Persistent write with a matching TTL extension: not flagged.
    pub fn save_profile(env: Env, user: Address, score: u32) {
        user.require_auth();
        let key = Symbol::new(&env, "profile");
        env.storage().persistent().set(&key, &score);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Temporary write with no TTL extension for this tier. The entry is
    /// left to expire on the temporary-storage schedule; the file-level
    /// storage rule does not report it because another tier is extended.
    pub fn open_session(env: Env, user: Address, session: Symbol, expiry: u64) {
        user.require_auth();
        env.storage().temporary().set(&session, &expiry);
    }

    /// Instance TTL extension: keyless signature, threshold + extend_to.
    pub fn touch_instance(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().extend_ttl(100, 200);
    }

    /// Read-only profile lookup: reads persistent storage, writes nothing.
    pub fn read_profile(env: Env) -> u32 {
        let key = Symbol::new(&env, "profile");
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
