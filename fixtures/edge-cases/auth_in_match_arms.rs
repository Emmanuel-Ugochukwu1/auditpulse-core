//! Edge-case fixture: require_auth performed inside match arms.
//!
//! Positional ordering within the function body determines whether the first
//! sensitive operation appears after the first require_auth call.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct MatchArmAuthContract;

#[contractimpl]
impl MatchArmAuthContract {
    /// Auth appears in the match arm before the sensitive transfer executes.
    pub fn gated_in_match(
        env: Env,
        token: Address,
        caller: Address,
        to: Address,
        mode: u32,
        amount: i128,
    ) {
        let client = token::Client::new(&env, &token);
        match mode {
            0 => {
                caller.require_auth();
                client.transfer(&caller, &to, &amount);
            }
            _ => {
                caller.require_auth();
            }
        }
    }

    /// First match arm performs a transfer before any require_auth appears.
    pub fn ungated_first_arm(
        env: Env,
        token: Address,
        caller: Address,
        to: Address,
        mode: u32,
        amount: i128,
    ) {
        let client = token::Client::new(&env, &token);
        match mode {
            0 => {
                client.transfer(&caller, &to, &amount);
            }
            _ => {
                caller.require_auth();
            }
        }
    }
}
