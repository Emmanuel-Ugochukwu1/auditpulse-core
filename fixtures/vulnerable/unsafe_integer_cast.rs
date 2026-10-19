//! Vulnerable fixture: narrowing integer casts on amount-like values.
//! Expected findings: AP-CAST-001.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct NarrowingVault;

#[contractimpl]
impl NarrowingVault {
    /// Narrowing cast on fee from i128 to u64
    pub fn process_fee(env: Env, fee: i128) -> u64 {
        let small_fee = fee as u64;
        small_fee
    }

    /// Narrowing cast on amount from i128 to u32
    pub fn convert_amount(env: Env, amount: i128) -> u32 {
        let compact = amount as u32;
        compact
    }
}
