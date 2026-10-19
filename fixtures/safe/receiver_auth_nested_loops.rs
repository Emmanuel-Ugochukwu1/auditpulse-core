//! Safe fixture: receiver-form auth (`user.require_auth()`) on non-env receivers
//! combined with nested if-blocks and loop iterations.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Vec};

#[contract]
pub struct ReceiverAuthNestedLoopVault;

#[contractimpl]
impl ReceiverAuthNestedLoopVault {
    /// Receiver-form require_auth ahead of nested loops and blocks.
    pub fn batch_payout(
        env: Env,
        token: Address,
        user: Address,
        recipients: Vec<Address>,
        amount: i128,
    ) {
        user.require_auth();
        assert!(token != env.current_contract_address());

        let client = token::Client::new(&env, &token);
        for recipient in recipients.iter() {
            if amount > 0 {
                client.transfer(&user, &recipient, &amount);
            }
        }
    }
}
