//! Sample Soroban smart contract demonstrating complex macro expansions
//! and temporary vs. persistent storage TTL extensions under edge-case logic.
//!
//! Used as a scan target and test fixture for AuditPulse scanner rules.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, BytesN, Env, Symbol,
};

macro_rules! require_auth {
    ($signer:expr) => {
        $signer.require_auth();
    };
}

macro_rules! extend_persistent_ttl {
    ($env:expr, $key:expr, $threshold:expr, $extend_to:expr) => {
        $env.storage().persistent().extend_ttl(&$key, $threshold, $extend_to);
    };
}

macro_rules! extend_temporary_ttl {
    ($env:expr, $key:expr, $threshold:expr, $extend_to:expr) => {
        $env.storage().temporary().extend_ttl(&$key, $threshold, $extend_to);
    };
}

macro_rules! bump_storage_ttl {
    (persistent, $env:expr, $key:expr) => {
        $env.storage().persistent().extend_ttl(&$key, 17280, 518400);
    };
    (temporary, $env:expr, $key:expr) => {
        $env.storage().temporary().extend_ttl(&$key, 100, 1000);
    };
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    PersistentBalance(Address),
    TemporarySession(Address),
    Config,
}

#[contract]
pub struct MacroExpandedVault;

#[contractimpl]
impl MacroExpandedVault {
    /// Safe: Protected by require_auth! macro and bumps persistent storage TTL via macro.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        require_auth!(from);
        let key = DataKey::PersistentBalance(from.clone());
        env.storage().persistent().set(&key, &amount);
        extend_persistent_ttl!(env, key, 17280, 518400);
    }

    /// Safe: Manages temporary storage TTL extension via macro under edge-case session logic.
    pub fn create_session(env: Env, user: Address, session_id: i128) {
        require_auth!(user);
        let key = DataKey::TemporarySession(user.clone());
        env.storage().temporary().set(&key, &session_id);
        extend_temporary_ttl!(env, key, 100, 1000);
    }

    /// Safe: Manages cross-tier storage with compound bump_storage_ttl! macro.
    pub fn refresh_state(env: Env, user: Address) {
        require_auth!(user);
        let p_key = DataKey::PersistentBalance(user.clone());
        let t_key = DataKey::TemporarySession(user.clone());
        bump_storage_ttl!(persistent, env, p_key);
        bump_storage_ttl!(temporary, env, t_key);
    }

    /// Safe upgrade: Protected by require_auth! macro invocation.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        require_auth!(admin);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Vulnerable: Performs token transfer without auth guard. Triggers AP-AUTH-001.
    pub fn unprotected_withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &to);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
