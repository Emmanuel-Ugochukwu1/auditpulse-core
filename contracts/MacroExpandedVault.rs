//! Sample Soroban smart contract demonstrating complex macro expansion handling:
//! 1. Local macro_rules! authorization check (auth_guard!)
//! 2. Attribute macro authorization boundary (#[only_owner])
//! 3. Unguarded operation flagged by AP-AUTH-001

use soroban_sdk::{
    contract, contractimpl, token, Address, Env, Symbol,
};

macro_rules! auth_guard {
    ($env:expr, $account:expr) => {
        $env.require_auth($account);
    };
}

#[contract]
pub struct MacroExpandedVault;

#[contractimpl]
impl MacroExpandedVault {
    /// Guarded by local macro_rules! expansion: safe, not flagged.
    pub fn withdraw_with_macro(env: Env, to: Address, amount: i128) {
        auth_guard!(&env, &to);
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Guarded by procedural attribute macro: safe, not flagged.
    #[only_owner]
    pub fn emergency_drain(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Intentionally unguarded function: must be flagged by AP-AUTH-001.
    pub fn unauthorized_transfer(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    fn token_id(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .unwrap_or_else(|| panic!("token unset"))
    }
}
