//! Sample Soroban smart contract demonstrating temporary vs. persistent storage
//! TTL extensions under edge-case logic, used for scanner validation and CI/CD SARIF reports.
//!
//! Intentionally contains un-extended persistent and temporary storage writes,
//! plus unwrap on storage reads, to test AP-STORAGE-001 and AP-ERROR-001.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageCi;

#[contractimpl]
impl TtlStorageCi {
    /// Writes to persistent storage without extending TTL.
    /// Triggers AP-STORAGE-001 because persistent ledger entries can expire.
    pub fn save_persistent(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&user, &amount);
        // Missing extend_ttl call here!
    }

    /// Writes to temporary storage without extending TTL.
    /// Temporary entries have a short lifespan and will be purged without extension.
    pub fn save_temporary(env: Env, session_user: Address, session_id: Symbol, val: i128) {
        session_user.require_auth();
        env.storage().temporary().set(&session_id, &val);
        // Missing extend_ttl call here!
    }

    /// Reads from persistent storage using .unwrap(), which panics if the entry has expired.
    pub fn load_persistent(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&user)
            .unwrap()
    }

    /// Commented-out TTL extension does not satisfy the rule.
    pub fn commented_ttl(env: Env, admin: Address, key: Symbol, value: i128) {
        admin.require_auth();
        env.storage().instance().set(&key, &value);
        // env.storage().instance().extend_ttl(&key, 100, 200);
    }
}
