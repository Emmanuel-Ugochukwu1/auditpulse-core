//! Edge-case TTL / storage-expiration fixture — UNMANAGED tier.
//!
//! Companion to `TtlStorageManaged.rs` (issue #3). This contract writes and
//! reads BOTH ledger storage tiers without ever bumping the entry:
//!
//! * persistent storage (`DataKey::Balance`) — long-lived but still expires
//!   and then reads back as `None`, so the `.unwrap_or(0)` below silently
//!   resets a balance that should still exist;
//! * temporary storage (`DataKey::Nonce`) — the shortest-lived tier, gone the
//!   fastest if it is never extended.
//!
//! Because no `extend_ttl` / `extend_ttl_to_threshold` / `get_extended` call
//! appears anywhere in the file, the file-level rule reports it.
//! Expected finding: **AP-STORAGE-001** (plus AP-ERROR-001 on the `.unwrap()`).
//!
//! Scan directly:
//! `npx tsx src/index.ts contracts/TtlStorageTiers.rs`

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Symbol),
    Config,
}

#[contract]
pub struct UnmanagedTtlVault;

#[contractimpl]
impl UnmanagedTtlVault {
    /// Persistent write with no `extend_ttl`: the balance entry expires and
    /// later reads return `None` even though the account still exists.
    pub fn deposit_persistent(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Temporary write with no bump: temporary entries have the shortest
    /// ledger TTL and vanish fastest.
    pub fn record_nonce(env: Env, tag: Symbol, value: u64) {
        env.storage().temporary().set(&DataKey::Nonce(tag), &value);
    }

    /// Persistent read with no bump: an already-expired entry reads `None`
    /// and the `.unwrap()` below turns that into a panic.
    pub fn config_or_panic(env: Env) -> Symbol {
        env.storage()
            .persistent()
            .get::<DataKey, Symbol>(&DataKey::Config)
            .unwrap()
    }
}
