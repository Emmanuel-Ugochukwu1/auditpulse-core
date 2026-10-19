//! Safe fixture: authorization performed inside intra-file helper functions
//! that consist solely of auth checks.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};

#[contract]
pub struct HelperAuthGatedVault;

#[contractimpl]
impl HelperAuthGatedVault {
    /// Token transfer gated by an intra-file helper function.
    pub fn withdraw(
        env: Env,
        token_id: Address,
        user: Address,
        recipient: Address,
        amount: i128,
    ) {
        Self::verify_caller(&env, &user);
        assert!(token_id != env.current_contract_address());

        let client = token::Client::new(&env, &token_id);
        client.transfer(&user, &recipient, &amount);
    }

    /// Pure authorization helper function.
    fn verify_caller(env: &Env, user: &Address) {
        env.require_auth(user);
    }

    /// Storage write gated by another helper defined after caller.
    pub fn record_state(env: Env, admin: Address, val: i128) {
        admin_gate(&admin);

        env.storage().instance().set(&symbol_short!("val"), &val);
        env.storage().instance().extend_ttl(&symbol_short!("val"), 100, 200);
    }
}

/// Standalone pure authorization helper.
fn admin_gate(admin: &Address) {
    admin.require_auth();
}
