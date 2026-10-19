//! Safe fixture: safe checked conversions without narrowing `as` casts.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafeConversionVault;

#[contractimpl]
impl SafeConversionVault {
    /// Safe conversion using try_into
    pub fn process_fee(env: Env, fee: i128) -> Result<u64, Error> {
        let safe_fee: u64 = fee.try_into().map_err(|_| Error::Overflow)?;
        Ok(safe_fee)
    }

    /// Safe conversion using u32::try_from
    pub fn convert_amount(env: Env, amount: i128) -> Option<u32> {
        u32::try_from(amount).ok()
    }

    /// Non-amount cast is ignored
    pub fn loop_step(idx: usize) -> u32 {
        let step = idx as u32;
        step
    }
}
