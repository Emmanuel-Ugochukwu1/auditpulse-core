//! Safe fixture: deposit and withdraw entrypoints with explicit amount bounds.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct BoundedVault;

#[contractimpl]
impl BoundedVault {
    /// Deposit strictly requiring amount > 0 with auth, checked math, and TTL extension
    pub fn deposit(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&user);
        assert!(amount > 0, "amount must be positive");
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        let new_bal = balance.checked_add(amount).ok_or(Error::Overflow)?;
        env.storage().persistent().set(&user, &new_bal);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        Ok(())
    }

    /// Withdraw with positivity check, auth, checked math, and balance verification
    pub fn withdraw(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&user);
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        let remaining = balance.checked_sub(amount).ok_or(Error::InsufficientFunds)?;
        env.storage().persistent().set(&user, &remaining);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        Ok(())
    }
}
