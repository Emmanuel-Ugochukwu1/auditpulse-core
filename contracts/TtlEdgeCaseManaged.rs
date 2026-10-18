//! Clean counterpart to `TtlEdgeCaseMatrix.rs`.
//!
//! Expected findings from `npx tsx src/index.ts contracts/TtlEdgeCaseManaged.rs`:
//! - No AP-STORAGE-001 — every storage access is paired with
//!   `extend_ttl`/`extend_ttl_to_threshold`.
//! - No AP-AUTH-001 — every storage-mutating function calls
//!   `env.require_auth(...)` before touching storage.
//! - No AP-UNWRAP-001 — every fallible read goes through a
//!   `Result`-shaped return path.
//!
//! The contract intentionally mirrors the public surface of
//! `TtlEdgeCaseMatrix.rs` so the two fixtures can be compared function
//! for function in the test suite.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct TtlKey {
    pub owner: Symbol,
    pub bucket: Symbol,
}

#[contract]
pub struct TtlEdgeCaseManaged;

#[contractimpl]
impl TtlEdgeCaseManaged {
    /// Writes to persistent storage, authenticates the caller, and bumps
    /// the TTL on the exact key it just wrote.
    pub fn store_persistent(env: Env, owner: Address, value: u64) -> Result<(), &'static str> {
        owner.require_auth()?;
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "value"),
        };
        env.storage().persistent().set(&key, &value);
        env.storage()
            .persistent()
            .extend_ttl(&key, 100, 200);
        Ok(())
    }

    /// Reads persistent storage, returns `Result` instead of `.unwrap()`,
    /// and explicitly extends TTL on the read path before returning.
    pub fn load_persistent_or_panic(env: Env, owner: Address) -> Result<u64, &'static str> {
        owner.require_auth()?;
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "value"),
        };
        if !env.storage().persistent().has(&key) {
            return Err("missing");
        }
        env.storage()
            .persistent()
            .extend_ttl(&key, 100, 200);
        env.storage().persistent().get(&key).ok_or("missing")
    }

    /// Writes to instance storage with authentication and TTL bump.
    pub fn store_instance(env: Env, owner: Address, value: u64) -> Result<(), &'static str> {
        owner.require_auth()?;
        let key = Symbol::new(&env, "value");
        env.storage().instance().set(&key, &value);
        env.storage().instance().extend_ttl(&key, 100, 200);
        Ok(())
    }

    /// Unconditional TTL extension on every code path that returns Ok.
    pub fn store_with_conditional_extend(
        env: Env,
        owner: Address,
        value: u64,
    ) -> Result<(), &'static str> {
        owner.require_auth()?;
        let key = TtlKey {
            owner: Symbol::new(&env, "owner"),
            bucket: Symbol::new(&env, "cond"),
        };
        env.storage().persistent().set(&key, &value);
        env.storage()
            .persistent()
            .extend_ttl_to_threshold(&key, 100);
        Ok(())
    }
}