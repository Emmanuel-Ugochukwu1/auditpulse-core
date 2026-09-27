//! Sample Soroban contract used as a scan target for AuditPulse's
//! storage-expiration rule (AP-STORAGE-001).
//!
//! It intentionally pairs risky and safe versions of the same patterns so
//! the scanner's file-level TTL behaviour can be demonstrated end to end:
//!
//! - `risky_read` / `risky_write`: ledger entries are used without any
//!   `extend_ttl` bump anywhere in the file's other functions, so the
//!   file-level rule reports the first access.
//! - `bumped_read` / `bumped_write`: every access is followed by an
//!   `extend_ttl` call and writes stay admin-gated.
//!
//! Scan it with: `npx ts-node src/index.ts contracts/TtlStorageEdgeCases.rs`

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageEdgeCases;

#[contractimpl]
impl TtlStorageEdgeCases {
    /// Risky: persistent entry read without any TTL bump.
    pub fn risky_read(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "counter"))
            .unwrap_or(0)
    }

    /// Risky: temporary entry written without any TTL bump.
    pub fn risky_write(env: Env, admin: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(&Symbol::new(&env, "session"), &1_u32);
    }

    /// Safe: the read is followed by an extend_ttl bump.
    pub fn bumped_read(env: Env) -> u32 {
        let key = Symbol::new(&env, "counter");
        let value = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().extend_ttl(&key, 100, 200);
        value
    }

    /// Safe: admin-gated write with a threshold-based bump.
    pub fn bumped_write(env: Env, admin: Address, value: u32) {
        admin.require_auth();
        let key = Symbol::new(&env, "counter");
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().extend_ttl_to_threshold(&key, 200);
    }
}
