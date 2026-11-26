//! Static-analysis fixture for authorization and TTL boundaries introduced by
//! local `macro_rules!` wrappers or outer attributes. This file is scanning
//! input, not a deployable reference implementation.

use soroban_sdk::{contractimpl, token, Address, BytesN, Env, Symbol};

macro_rules! auth_gate {
    ($env:expr, $account:expr) => {
        $env.require_auth($account);
    };
}

macro_rules! nested_auth_gate {
    ($env:expr, $account:expr) => {
        auth_gate!($env, $account);
    };
}

macro_rules! checked_ttl {
    ($storage:expr, $key:expr) => {
        $storage.extend_ttl($key, 100, 500);
    };
}

macro_rules! log_only {
    ($message:expr) => {
        $message
    };
}

#[contractimpl]
impl MacroExpansionBoundaries {
    /// SAFE: the attribute expands to authorization before the body.
    #[when_not_paused]
    #[stellar_macros::only_owner]
    pub fn attribute_guarded(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// VULNERABLE: `has_role` checks membership but does not sign the call.
    #[has_role(caller, "operator")]
    pub fn role_check_only(env: Env, to: Address, amount: i128, caller: Address) {
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// SAFE: the local macro directly expands to `require_auth`.
    pub fn direct_macro_guard(env: Env, to: Address, amount: i128) {
        auth_gate!(&env, &to);
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// SAFE: wrappers are followed transitively.
    pub fn nested_macro_guard(env: Env, to: Address, amount: i128) {
        nested_auth_gate!(&env, &to);
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// VULNERABLE: authorization runs after the transfer.
    pub fn late_macro_guard(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
        auth_gate!(&env, &to);
    }

    /// VULNERABLE: a non-auth macro does not hide the operation.
    pub fn unrelated_macro(env: Env, to: Address, amount: i128) {
        log_only!("transfer");
        let client = token::Client::new(&env, &Self::token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// SAFE for AP-UPG-001: a nested macro supplies the admin authorization.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        nested_auth_gate!(&env, &admin);
        env.storage().instance().set(&Symbol::new(&env, "wasm"), &new_wasm_hash);
    }

    /// SAFE for AP-STORAGE-001: the local macro performs the TTL extension.
    pub fn touch(env: Env, key: Symbol) -> Option<i64> {
        let storage = env.storage().persistent();
        checked_ttl!(&storage, &key);
        storage.get(&key)
    }

    fn token(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .unwrap_or_else(|| panic!("token not set"))
    }
}
