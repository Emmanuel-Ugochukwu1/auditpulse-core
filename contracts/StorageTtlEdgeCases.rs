//! Sample Soroban smart contract for AuditPulse TTL edge cases.
//!
//! This contract exercises the AP-STORAGE-001 ("Missing Extend TTL") rule
//! with temporary vs. persistent storage under edge-case logic.
//!
//! What the rule checks (file-level): if a file touches ledger storage
//! (`env.storage().temporary()`, `.persistent()` or `.instance()`) but
//! contains NO `extend_ttl` / `extend_ttl_to_threshold` / `get_extended`
//! call anywhere, the entries can silently expire, so the scanner reports
//! exactly one AP-STORAGE-001 finding at the FIRST storage access in the
//! file. Comments do not count: the scanner strips them before checking,
//! so an `extend_ttl` mentioned only in a comment does not suppress the
//! finding. String literals are NOT stripped by this rule, so an
//! `extend_ttl` written only inside a string would (incorrectly) suppress
//! it — that behaviour is documented in the unit test, not endorsed here.
//!
//! This file intentionally contains NO real `extend_ttl` call, so scanning
//! it must produce exactly one AP-STORAGE-001 finding, located at the first
//! storage access in `read_temp_without_bump`.
//!
//! Scan it with: `npx tsx src/cli.ts scan contracts/StorageTtlEdgeCases.rs`
//! (or `npm test`, which runs the matching unit test).

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct DataKey {
    pub config: Symbol,
    pub balance: Symbol,
}

#[contract]
pub struct StorageTtlEdgeCases;

#[contractimpl]
impl StorageTtlEdgeCases {
    /// Temporary storage read with NO extend_ttl anywhere in this file.
    /// This is the first storage access in the file, so AP-STORAGE-001
    /// points at this line.
    pub fn read_temp_without_bump(env: Env, key: Symbol) -> Option<i128> {
        env.storage().temporary().get(&key)
    }

    /// Persistent storage write with no extend_ttl. The entry is written
    /// but never bumped, so it can expire and read back as None later.
    pub fn write_persistent_without_bump(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
    }

    /// Instance storage read with no extend_ttl. Instance entries are
    /// ledger storage too, so the same expiry risk applies.
    pub fn read_instance_without_bump(env: Env, key: Symbol) -> Option<Address> {
        env.storage().instance().get(&key)
    }

    /// Edge case: `extend_ttl` is mentioned only in comments here.
    /// Comments are stripped before scanning, so this must NOT suppress
    /// the finding — the file still has no real extend_ttl call.
    pub fn bump_only_in_comment(env: Env, key: Symbol) -> Option<i128> {
        // extend_ttl would keep this alive, but the call is missing.
        env.storage().temporary().get(&key)
    }
}
