//! Vulnerable fixture: deposit and withdraw entrypoints without amount bounds.
//! Expected findings: AP-BOUND-001.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct UnboundedVault;

#[contractimpl]
impl UnboundedVault {
    /// Deposit without positivity assertion allows zero or negative amounts
    pub fn deposit(env: Env, user: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance + amount));
    }

    /// Withdraw without positivity or bound assertion
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance - amount));
    }
}
