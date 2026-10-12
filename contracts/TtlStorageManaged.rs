//! Edge-case TTL / storage-expiration fixture — MANAGED tier.
//!
//! Companion to `TtlStorageTiers.rs` (issue #3). This is the same access
//! pattern as the unmanaged half, but every tier is kept alive:
//!
//! * persistent writes/reads are followed by `extend_ttl`;
//! * the temporary entry is bumped with `extend_ttl_to_threshold`.
//!
//! Expected finding: **none** — the storage rule stays silent because the
//! entries are explicitly extended.
//!
//! Scan directly:
//! `npx tsx src/index.ts contracts/TtlStorageManaged.rs`

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Symbol),
    Config,
}

#[contract]
pub struct ManagedTtlVault;

#[contractimpl]
impl ManagedTtlVault {
    /// Persistent write immediately followed by `extend_ttl`.
    pub fn deposit_persistent(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// Temporary write bumped with `extend_ttl_to_threshold`.
    pub fn record_nonce(env: Env, tag: Symbol, value: u64) {
        let key = DataKey::Nonce(tag);
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().extend_ttl_to_threshold(&key, 50, 100);
    }

    /// Persistent read guarded by an explicit extension.
    pub fn config(env: Env) -> Symbol {
        let key = DataKey::Config;
        env.storage().persistent().extend_ttl(&key, 100, 200);
        env.storage()
            .persistent()
            .get::<DataKey, Symbol>(&key)
            .unwrap_or(Symbol::new(&env, "unset"))
    }
}
