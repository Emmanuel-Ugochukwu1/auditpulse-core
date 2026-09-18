//! Sample Soroban contract with complex macro expansions and security helpers.
//!
//! Demonstrates declarative macro expansions (macro_rules!) for auth guards
//! and storage TTL management, proving scanner accuracy without false positives.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, BytesN, Env, Symbol,
};

macro_rules! require_auth {
    ($signer:expr) => {
        $signer.require_auth();
    };
}

macro_rules! extend_ttl {
    ($env:expr, $key:expr) => {
        $env.storage().persistent().extend_ttl(&$key, 17280, 518400);
    };
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Balance(Address),
    Admin,
}

#[contract]
pub struct MacroExpandedVault;

#[contractimpl]
impl MacroExpandedVault {
    /// Safe: Protected by require_auth! macro and bumps TTL via extend_ttl! macro.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        require_auth!(from);
        let key = DataKey::Balance(from.clone());
        env.storage().persistent().set(&key, &amount);
        extend_ttl!(env, key);
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
