//! Sample Soroban smart contract demonstrating un-extended temporary and
//! persistent storage writes under edge-case logic (commented-out extensions,
//! panicking unwrap on expired entries), used for scanner & SARIF validation.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageUnmanaged;

#[contractimpl]
impl TtlStorageUnmanaged {
    /// Writes to persistent storage without extending TTL (triggers AP-STORAGE-001).
    pub fn store_persistent_unextended(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);
        env.storage().persistent().set(&user, &amount);
    }

    /// Writes to temporary storage with only a commented-out extend_ttl call.
    pub fn store_temporary_unextended(
        env: Env,
        caller: Address,
        session_key: Symbol,
        value: i128,
    ) {
        env.require_auth(&caller);
        env.storage().temporary().set(&session_key, &value);
        // env.storage().temporary().extend_ttl(&session_key, 100, 200);
    }

    /// Reads persistent storage with .unwrap(), risking a panic if the entry expires (AP-ERROR-001).
    pub fn read_expired_with_unwrap(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&user).unwrap()
    }
}
