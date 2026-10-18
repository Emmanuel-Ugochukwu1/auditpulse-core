//! Safe fixture: intra-file helper functions whose bodies consist solely of
//! require_auth checks gate sensitive operations in callers when invoked
//! before the operation. Expected findings: none.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, Symbol};

const KEY_TREASURY: Symbol = symbol_short!("TREAS");

#[contract]
pub struct HelperGatedVault;

#[contractimpl]
impl HelperGatedVault {
    fn authorize(env: &Env, account: &Address) {
        env.require_auth(account);
    }

    /// Calls Self::authorize before a sensitive token transfer.
    pub fn withdraw(
        env: Env,
        token_id: Address,
        allowed_id: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        Self::authorize(&env, &from);
        assert!(token_id == allowed_id);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
    }

    /// Calls a helper defined later in the file before a storage write.
    pub fn update_vault_state(env: Env, operator: Address, treasury: Address) {
        require_operator(&operator);
        env.storage().instance().set(&KEY_TREASURY, &treasury);
        env.storage().instance().extend_ttl(100, 200);
    }
}

fn require_operator(operator: &Address) {
    operator.require_auth();
}
