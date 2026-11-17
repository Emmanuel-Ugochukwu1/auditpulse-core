//! Sample Soroban smart contract exercising temporary vs. persistent
//! storage access without active TTL extension under edge-case patterns.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum VaultStorageKey {
    TempNonce(Address),
    UserDeposit(Address),
    FrozenFlag,
}

#[contract]
pub struct TtlExpirationVault;

#[contractimpl]
impl TtlExpirationVault {
    /// Writes a temporary session nonce without calling extend_ttl.
    /// // env.storage().temporary().extend_ttl(&key, 100, 500);
    pub fn record_temp_nonce(env: Env, caller: Address, nonce: u64) {
        caller.require_auth();
        let key = VaultStorageKey::TempNonce(caller);
        env.storage().temporary().set(&key, &nonce);
    }

    /// Reads and updates persistent stake across conditional branches without TTL bump.
    pub fn stake_if_unfrozen(env: Env, staker: Address, delta: i128) -> i128 {
        staker.require_auth();
        let frozen: bool = env
            .storage()
            .instance()
            .get(&VaultStorageKey::FrozenFlag)
            .unwrap_or(false);
        if frozen {
            return 0;
        }
        let key = VaultStorageKey::UserDeposit(staker);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_add(delta).unwrap_or(current);
        /* env.storage().persistent().extend_ttl(&key, 1_000, 10_000); */
        env.storage().persistent().set(&key, &updated);
        updated
    }
}
