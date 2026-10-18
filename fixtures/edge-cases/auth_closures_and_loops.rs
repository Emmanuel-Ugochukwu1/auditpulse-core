//! Edge-case fixture: sensitive operations inside iterator closures.
//!
//! Covers .iter().for_each(|x| ...) with and without a preceding require_auth.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Vec};

#[contract]
pub struct ClosureAuthContract;

#[contractimpl]
impl ClosureAuthContract {
    /// Receiver-form require_auth precedes the closure-enclosed transfer.
    pub fn batch_payout_gated(
        env: Env,
        token: Address,
        sender: Address,
        recipients: Vec<Address>,
        share: i128,
    ) {
        sender.require_auth();
        let client = token::Client::new(&env, &token);
        recipients.iter().for_each(|recipient| {
            client.transfer(&sender, &recipient, &share);
        });
    }

    /// Sensitive transfer inside a closure with no require_auth in the function.
    pub fn batch_payout_ungated(
        env: Env,
        token: Address,
        sender: Address,
        recipients: Vec<Address>,
        share: i128,
    ) {
        let client = token::Client::new(&env, &token);
        recipients.iter().for_each(|recipient| {
            client.transfer(&sender, &recipient, &share);
        });
    }
}
