//! File-level extension scope.
//!
//! `managed` bumps its own persistent key; `unmanaged` touches temporary
//! storage and never extends it. AP-STORAGE-001 is deliberately file-level
//! today, so the extension in `managed` suppresses the whole file and the
//! `unmanaged` access goes unreported. This fixture pins that behaviour; a
//! function-level rule would need a separate change and a new expectation.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Nonce(Address),
}

#[contract]
pub struct TtlExtensionScope;

#[contractimpl]
impl TtlExtensionScope {
    pub fn managed(env: Env, owner: Address) -> i128 {
        let key = DataKey::Balance(owner);
        let value = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().extend_ttl(&key, 100, 200);
        value
    }

    pub fn unmanaged(env: Env, owner: Address) -> u64 {
        let key = DataKey::Nonce(owner);
        env.storage().temporary().get(&key).unwrap_or(0)
    }
}
