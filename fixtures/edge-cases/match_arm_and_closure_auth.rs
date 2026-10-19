//! Edge-case fixture: authorization performed inside match arms and
//! sensitive operations executed inside closures (iter().for_each()).
//!
//! Expected findings:
//! - AP-AUTH-001 on closure_ungated (sensitive operation in closure without auth).
//! - branch_auth and closure_gated are authorized and produce no findings.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Vec};

#[contract]
pub struct MatchAndClosureAuthVault;

#[contractimpl]
impl MatchAndClosureAuthVault {
    /// Authorization evaluated inside match arms preceding sensitive operations.
    pub fn branch_auth(
        env: Env,
        mode: u32,
        user: Address,
        token: Address,
        amount: i128,
    ) {
        match mode {
            0 => env.require_auth(&user),
            _ => user.require_auth(),
        }
        assert!(token != env.current_contract_address());
        let client = token::Client::new(&env, &token);
        client.transfer(&user, &env.current_contract_address(), &amount);
    }

    /// Sensitive operation inside a closure preceded by require_auth.
    pub fn closure_gated(
        env: Env,
        token: Address,
        user: Address,
        recipients: Vec<Address>,
        amount: i128,
    ) {
        env.require_auth(&user);
        assert!(token != env.current_contract_address());
        let client = token::Client::new(&env, &token);
        recipients.iter().for_each(|to| {
            client.transfer(&user, &to, &amount);
        });
    }

    /// Sensitive operation inside a closure without any authorization.
    pub fn closure_ungated(
        env: Env,
        token: Address,
        user: Address,
        recipients: Vec<Address>,
        amount: i128,
    ) {
        assert!(token != env.current_contract_address());
        let client = token::Client::new(&env, &token);
        recipients.iter().for_each(|to| {
            client.transfer(&user, &to, &amount);
        });
    }
}
