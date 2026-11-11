//! Vulnerable demo: Soroban ledger storage accessed without extending TTL.
//! Expected finding: AP-STORAGE-001 (one file-level finding at the first
//! storage access).
//!
//! The contract is deliberately clean in every other respect so the scan
//! isolates the TTL rule:
//!  * every ledger write is gated by `env.require_auth(&caller)` ahead of the
//!    `.set(...)` call, so AP-AUTH-001 stays silent;
//!  * no `.unwrap()` / `.expect()` / `panic!()`, so AP-ERROR-001 stays silent;
//!  * no arithmetic on amount-like values, so AP-ARITH-001 stays silent;
//!  * no token/client cross-contract calls, so AP-CALL-001 stays silent;
//!  * no admin/upgrade-shaped function names, so AP-UPG-001 stays silent;
//!  * no debug macros, so AP-DEBUG-001 stays silent.
//!
//! Edge cases exercised against the three storage tiers:
//!  * persistent storage read/write with no `extend_ttl`
//!  * temporary storage read with no `extend_ttl_to_threshold`
//!  * instance storage write with no `extend_ttl`
//!  * a commented-out `extend_ttl` that must NOT count as extension
//!  * a block-commented `extend_ttl` that must NOT count as extension
//!  * an `extend_ttl` mentioned in a doc string (without the leading dot,
//!    which the rule requires) that must NOT count as extension

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageEdgeCases;

#[contractimpl]
impl TtlStorageEdgeCases {
    /// Persistent storage written without extend_ttl: flagged.
    pub fn save_persistent(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().persistent().set(&key, &value);
    }

    /// Temporary storage read without extend_ttl_to_threshold: flagged.
    pub fn load_temporary(env: Env, caller: Address, key: Symbol) -> i128 {
        env.require_auth(&caller);
        env.storage().temporary().get(&key).unwrap_or_default()
    }

    /// Instance storage written without extend_ttl: flagged.
    pub fn save_instance(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().instance().set(&key, &value);
    }

    /// A line-commented extend_ttl must not count as extension.
    pub fn commented_extension(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().persistent().set(&key, &value);
        // env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// A block-commented extend_ttl must not count as extension.
    pub fn block_commented_extension(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().persistent().set(&key, &value);
        /* env.storage().persistent().extend_ttl(&key, 100, 200); */
    }

    /// A doc string mentioning extend_ttl (no leading dot) must not count.
    pub fn string_mention_extension(env: Env, caller: Address, key: Symbol, value: i128) {
        env.require_auth(&caller);
        env.storage().persistent().set(&key, &value);
        let doc = "call extend_ttl(&key, 100, 200) to keep this entry alive";
    }
}