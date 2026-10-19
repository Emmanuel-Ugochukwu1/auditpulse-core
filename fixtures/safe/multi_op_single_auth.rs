//! Safe fixture: multi-operation function performing token transfer,
//! instance storage update, and token burn, all gated once by a single
//! preceding require_auth call.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};

#[contract]
pub struct MultiOpSingleAuthVault;

#[contractimpl]
impl MultiOpSingleAuthVault {
    /// Multiple diverse sensitive operations (transfer, storage write, burn)
    /// authorized upfront by a single require_auth call.
    pub fn rebalance_and_burn(
        env: Env,
        token: Address,
        caller: Address,
        recipient: Address,
        amount: i128,
    ) {
        env.require_auth(&caller);
        assert!(token != env.current_contract_address());

        let client = token::Client::new(&env, &token);
        client.transfer(&caller, &recipient, &amount);

        env.storage().instance().set(&symbol_short!("last"), &amount);
        env.storage().instance().extend_ttl(&symbol_short!("last"), 100, 200);

        client.burn(&recipient, &amount);
    }
}
