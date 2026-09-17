//! Sample Soroban smart contract demonstrating properly managed TTL handling.
//!
//! Clean counterpart to `StorageTtlEdgeCases.rs`:
//! 1. Every persistent and temporary storage access is extended via `extend_ttl`.
//! 2. Fallible reads return `Result<T, Symbol>` instead of panicking with `.unwrap()`.
//! 3. Sensitive operations are gated with `require_auth`.
//!
//! Used as a clean scan target for AuditPulse:
//! `npx tsx src/index.ts contracts/StorageTtlManaged.rs`

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Symbol};

const DAY_IN_LEDGERS: u32 = 17_280;
const PERSISTENT_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const PERSISTENT_EXTEND_TO: u32 = 60 * DAY_IN_LEDGERS;
const TEMPORARY_THRESHOLD: u32 = 100;
const TEMPORARY_EXTEND_TO: u32 = 1_000;

#[contracttype]
pub enum StorageKey {
    Balance(Address),
    SessionAllowance(Address),
    Config,
}

#[contract]
pub struct StorageTtlManaged;

#[contractimpl]
impl StorageTtlManaged {
    /// Persistent write with proper authentication and TTL extension.
    pub fn set_balance(env: Env, user: Address, amount: i128) -> Result<(), Symbol> {
        env.require_auth(&user);
        let key = StorageKey::Balance(user);
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
        Ok(())
    }

    /// Safe persistent read: avoids .unwrap() and bumps TTL on access.
    pub fn get_balance(env: Env, user: Address) -> Result<i128, Symbol> {
        let key = StorageKey::Balance(user);
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Symbol::new(&env, "not_found"))?;
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
        Ok(balance)
    }

    /// Temporary storage write with managed TTL lease.
    pub fn grant_session(env: Env, user: Address, allowance: i128) -> Result<(), Symbol> {
        env.require_auth(&user);
        let key = StorageKey::SessionAllowance(user);
        env.storage().temporary().set(&key, &allowance);
        env.storage().temporary().extend_ttl(
            &key,
            TEMPORARY_THRESHOLD,
            TEMPORARY_EXTEND_TO,
        );
        Ok(())
    }

    /// Authorized transfer with safe persistent state update and TTL bump.
    pub fn withdraw(env: Env, user: Address, token_id: Address, amount: i128) -> Result<(), Symbol> {
        env.require_auth(&user);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &user, &amount);
        let key = StorageKey::Balance(user);
        env.storage().persistent().set(&key, &0i128);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
        Ok(())
    }
}

