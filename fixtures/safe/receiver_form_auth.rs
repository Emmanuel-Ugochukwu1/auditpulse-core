//! Safe fixture: receiver-form require_auth on non-env Address receivers
//! combined with nested blocks and loops. Expected findings: none.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Vec};

#[contract]
pub struct ReceiverAuthVault;

#[contractimpl]
impl ReceiverAuthVault {
    /// Receiver-form auth on caller before nested conditional transfer.
    pub fn conditional_payout(
        env: Env,
        token: Address,
        from: Address,
        to: Address,
        amount: i128,
        allow_settlement: bool,
    ) {
        from.require_auth();
        let client = token::Client::new(&env, &token);
        if allow_settlement {
            {
                client.transfer(&from, &to, &amount);
            }
        }
    }

    /// Receiver-form auth with explicit args before a loop of transfers.
    pub fn batch_distribute(
        env: Env,
        token: Address,
        operator: Address,
        recipients: Vec<Address>,
        unit_amount: i128,
    ) {
        operator.require_auth_for_args(&(recipients.len(), unit_amount));
        let client = token::Client::new(&env, &token);
        for recipient in recipients.iter() {
            if unit_amount > 0 {
                client.transfer(&operator, &recipient, &unit_amount);
            }
        }
    }
}
