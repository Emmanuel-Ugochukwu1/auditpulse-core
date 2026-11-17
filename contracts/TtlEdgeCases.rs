//! Edge-case TTL coverage for AuditPulse scan tests.
//!
//! Exercises the boundary of AP-STORAGE-001: the rule is file-level, so a
//! single extend_ttl anywhere in the file silences it — even when other
//! storage entries are written but never bumped. This contract keeps a
//! bumped temporary entry alongside a persistent entry that expires
//! silently, which is the partial-coverage edge case under test.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Temporary entry written and bumped in the same call.
    pub fn open_session(env: Env, user: Address, data: i128) {
        user.require_auth();
        let key = Symbol::new(&env, "session");
        env.storage().temporary().set(&key, &data);
        env.storage().temporary().extend_ttl(&key, 50, 100);
    }

    /// Persistent entry written with no TTL extension of its own.
    /// The file-level TTL rule stays silent because open_session bumps
    /// its own entry — the edge case this contract documents.
    pub fn set_config(env: Env, admin: Address, data: i128) {
        admin.require_auth();
        let key = Symbol::new(&env, "config");
        env.storage().persistent().set(&key, &data);
    }

    /// Threshold-style bump on the temporary entry.
    pub fn refresh_session(env: Env, user: Address) {
        user.require_auth();
        let key = Symbol::new(&env, "session");
        env.storage()
            .temporary()
            .extend_ttl_to_threshold(&key, 50, 100);
    }
}
