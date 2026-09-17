//! Sample Soroban contract: correctly managed TTL handling.
//!
//! Clean counterpart to `TtlEdgeCases.rs`: every persistent/temporary entry
//! is kept alive via extend_ttl / extend_ttl_to_threshold, sensitive writes
//! are authorized, and fallible reads propagate via Result.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Symbol};

const DAY_IN_LEDGERS: u32 = 17_280;
const PERSIST_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const PERSIST_EXTEND: u32 = 60 * DAY_IN_LEDGERS;

#[contracttype]
pub enum TtlKey {
    Balance(Address),
    SessionAllowance(Address),
    Config,
}

#[contract]
pub struct TtlManaged;

#[contractimpl]
impl TtlManaged {
    /// Persistent write followed by an explicit extend_ttl.
    pub fn set_balance(env: Env, user: Address, amount: i128) -> Result<(), Symbol> {
        env.require_auth(&user);
        let key = TtlKey::Balance(user);
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(
            &key,
            PERSIST_THRESHOLD,
            PERSIST_EXTEND,
        );
        Ok(())
    }

    /// Fallible persistent read with error propagation instead of .unwrap().
    pub fn get_balance(env: Env, user: Address) -> Result<i128, Symbol> {
        let key = TtlKey::Balance(user);
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Symbol::new(&env, "not_found"))?;
        env.storage().persistent().extend_ttl(
            &key,
            PERSIST_THRESHOLD,
            PERSIST_EXTEND,
        );
        Ok(balance)
    }

    /// Temporary write whose TTL is actively managed.
    pub fn grant_session_allowance(env: Env, spender: Address, amount: i128) -> Result<(), Symbol> {
        env.require_auth(&spender);
        let key = TtlKey::SessionAllowance(spender);
        env.storage().temporary().set(&key, &amount);
        env.storage().temporary().extend_ttl(&key, 100, 200);
        Ok(())
    }

    /// Authorized token flush.
    pub fn flush(env: Env, user: Address, token_id: Address, amount: i128) -> Result<(), Symbol> {
        env.require_auth(&user);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&user, &env.current_contract_address(), &amount);
        let key = TtlKey::Balance(user);
        env.storage().persistent().set(&key, &0i128);
        env.storage().persistent().extend_ttl(
            &key,
            PERSIST_THRESHOLD,
            PERSIST_EXTEND,
        );
        Ok(())
    }
}
