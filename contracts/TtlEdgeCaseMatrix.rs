//! Vulnerable edge-case TTL fixture for AP-STORAGE-001 (#3).
//!
//! This contract intentionally exercises TTL/storage patterns that none of
//! the earlier unmanaged-TTL fixtures covered. Each scenario is documented
//! inline so a reviewer can map the scanner finding back to the offending
//! pattern.
//!
//! Expected findings from `npx tsx src/index.ts contracts/TtlEdgeCaseMatrix.rs`:
//! - AP-STORAGE-001 (file-level, fires once) — every storage access below
//!   is documented in the file's text as either missing `extend_ttl`
//!   entirely or as a call that lives only inside a `// ` line comment or
//!   inside a string literal. The rule's `removeComments` step strips
//!   both, leaving no surviving `extend_ttl` call in the source the
//!   rule evaluates.
//! - AP-AUTH-001 (one per protected storage-mutating function) — the
//!   auth-sensitive writers below omit `env.require_auth(...)`.
//! - AP-ERROR-001 — `.unwrap()` is called on a storage read that may be
//!   missing once the entry expires, producing a runtime panic instead
//!   of a `Result`-shaped error.
//!
//! Acceptance: this fixture should produce findings when scanned and must
//! not silently regress to a clean report.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct TtlKey {
    pub owner: Symbol,
    pub bucket: Symbol,
}

#[contract]
pub struct TtlEdgeCaseMatrix;

#[contractimpl]
impl TtlEdgeCaseMatrix {
    /// Writes to persistent storage without authenticating the caller and
    /// without ever calling `extend_ttl`. Triggers AP-AUTH-001 (no
    /// `require_auth` before a storage mutation) and contributes to the
    /// file-level AP-STORAGE-001 finding.
    pub fn store_persistent(env: Env, owner: Address, value: u64) {
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "value"),
        };
        env.storage().persistent().set(&key, &value);
    }

    /// Reads persistent storage then unwraps the `Option`. After expiry the
    /// read returns `None` and `.unwrap()` panics. Triggers AP-ERROR-001
    /// and reinforces the AP-STORAGE-001 file-level finding (the file
    /// never extends TTL on this handle).
    pub fn load_persistent_or_panic(env: Env, owner: Address) -> u64 {
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "value"),
        };
        env.storage()
            .persistent()
            .get(&key)
            .unwrap()
    }

    /// Writes to *instance* storage (not persistent) without extend_ttl.
    /// Instance storage is also subject to TTL under Soroban and the
    /// AP-STORAGE-001 file-level check fires the moment `storage().` is
    /// seen anywhere in the file, regardless of which handle is touched.
    pub fn store_instance(env: Env, value: u64) {
        env.storage().instance().set(&Symbol::new(&env, "value"), &value);
    }

    /// Demonstrates the comment-shadowing case: the `extend_ttl` call
    /// below is on a `//` line comment and therefore stripped before the
    /// rule evaluates the file. A naive reader would assume TTL is being
    /// extended; the scanner correctly reports the file as vulnerable.
    pub fn store_with_shadowed_extend(env: Env, owner: Address, value: u64) {
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "shadow"),
        };
        env.storage().persistent().set(&key, &value);
        // env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Demonstrates the conditional extend case: the `extend_ttl` text
    /// below lives only inside a `// ` line comment. The scanner is
    /// intentionally file-level, so the file as a whole does not
    /// unconditionally extend TTL and is reported.
    pub fn store_with_conditional_extend(env: Env, owner: Address, value: u64) {
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "cond"),
        };
        env.storage().persistent().set(&key, &value);
        if value == 0 {
            // The line below is a comment: removeComments strips it before
            // the rule sees the file, so it does not count as a real TTL
            // extension even though a casual reader might assume so.
            // env.storage().persistent().extend_ttl(&key, 100, 200);
            return;
        }
    }
}