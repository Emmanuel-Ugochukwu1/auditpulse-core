//! Sample Soroban smart contract demonstrating temporary, persistent, and
//! instance storage TTL extensions under edge-case logic.
//!
//! All storage accesses in this contract are properly accompanied by TTL
//! extensions (`extend_ttl`, `extend_ttl_to_threshold`, or `get_extended`),
//! explicit authorization (`require_auth`), and checked arithmetic.
//! Expected scanner findings: 0.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
#[derive(Clone)]
pub enum StorageTierKey {
    PersistentBalance(Address),
    TemporaryQuote(u32),
    InstanceLastSeen,
}

#[contract]
pub struct TtlStorageEdgeCases;

#[contractimpl]
impl TtlStorageEdgeCases {
    /// Persistent balance write accompanied by explicit `extend_ttl`.
    pub fn deposit_persistent(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);

        let key = StorageTierKey::PersistentBalance(user);
        let storage = env.storage().persistent();
        let current: i128 = storage.get(&key).unwrap_or(0);
        let next = match current.checked_add(amount) {
            Some(value) => value,
            None => return,
        };
        storage.set(&key, &next);
        storage.extend_ttl(&key, 17_280, 518_400);
    }

    /// Temporary session/quote entry kept alive via `extend_ttl_to_threshold`.
    pub fn record_temporary_quote(env: Env, caller: Address, quote_id: u32) -> u32 {
        env.require_auth(&caller);

        let key = StorageTierKey::TemporaryQuote(quote_id);
        let storage = env.storage().temporary();
        let next = match storage.get(&key) {
            Some(count) => match count.checked_add(1u32) {
                Some(bumped) => bumped,
                None => count,
            },
            None => 1u32,
        };
        storage.set(&key, &next);
        storage.extend_ttl_to_threshold(&key, 100);
        next
    }

    /// Read-only path that bumps persistent storage TTL as a side effect.
    pub fn peek_extended_balance(env: Env, user: Address) -> Option<i128> {
        let key = StorageTierKey::PersistentBalance(user);
        env.storage().persistent().get_extended(&key)
    }

    /// Instance storage TTL bump accompanied by explicit admin authorization.
    pub fn heartbeat_instance(env: Env, admin: Address) {
        env.require_auth(&admin);
        let key = symbol_key(&env);
        env.storage().instance().set(&key, &1u32);
        env.storage().instance().extend_ttl(100, 1_000);
    }
}

fn symbol_key(env: &Env) -> Symbol {
    Symbol::new(env, "heartbeat")
}
