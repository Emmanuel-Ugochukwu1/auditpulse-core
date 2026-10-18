//! Safe fixture: multi-operation functions (transfer + storage write + burn)
//! gated once, and sub-contract client calls alongside token client calls.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, Symbol};

const KEY_SETTLED: Symbol = symbol_short!("SETTLED");

#[contract]
pub struct MultiOpCoordinator;

#[contractimpl]
impl MultiOpCoordinator {
    /// One auth check gates a token transfer, a storage write, and a token burn.
    pub fn settle_and_burn(
        env: Env,
        token: Address,
        user: Address,
        treasury: Address,
        payout: i128,
        burn_share: i128,
    ) {
        user.require_auth();
        let client = token::Client::new(&env, &token);
        client.transfer(&user, &treasury, &payout);
        env.storage().instance().set(&KEY_SETTLED, &user);
        env.storage().instance().extend_ttl(100, 200);
        client.burn(&user, &burn_share);
    }

    /// Sub-contract client call alongside a token client call, both gated once.
    pub fn routed_swap(
        env: Env,
        token: Address,
        router: Address,
        trader: Address,
        recipient: Address,
        amount: i128,
    ) {
        trader.require_auth();
        let sub_client = RouterClient::new(&env, &router);
        let token_client = token::Client::new(&env, &token);
        sub_client.record_route(&trader, &recipient);
        token_client.transfer(&trader, &recipient, &amount);
    }
}
