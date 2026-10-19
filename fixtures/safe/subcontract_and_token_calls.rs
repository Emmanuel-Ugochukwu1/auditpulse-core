//! Safe fixture: sub-contract client calls alongside token client calls
//! in the same function, verifying that auth correctly gates both clients.
//! Expected findings: none.

use soroban_sdk::{contract, contractclient, contractimpl, token, Address, Env};

#[contractclient(name = "SubContractClient")]
pub trait SubContract {
    fn notify(env: Env, user: Address);
}

#[contract]
pub struct SubcontractAndTokenVault;

#[contractimpl]
impl SubcontractAndTokenVault {
    /// Function invoking both token client and sub-contract client, gated by user auth.
    pub fn dispatch_composite(
        env: Env,
        token: Address,
        sub_target: Address,
        user: Address,
        amount: i128,
    ) {
        env.require_auth(&user);
        assert!(token != env.current_contract_address());
        assert!(sub_target != env.current_contract_address());

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let sub_client = SubContractClient::new(&env, &sub_target);
        sub_client.notify(&user);
    }
}
