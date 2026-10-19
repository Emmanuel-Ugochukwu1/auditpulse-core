//! Vulnerable fixture: functions with non-conventional upgrade/admin names
//! that exhibit structural signals (BytesN<32> wasm-hash storage writes,
//! admin/upgrade storage keys) without authorization.
//!
//! Expected findings: AP-UPG-001 (one for commit_bytecode, one for reassign_authority).
//! apply_patch is gated by require_auth so it is safe.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct StructuralUpgradeVault;

#[contractimpl]
impl StructuralUpgradeVault {
    /// Non-conventional name 'commit_bytecode' writes a BytesN<32> wasm hash to storage with no auth check.
    pub fn commit_bytecode(env: Env, new_code_hash: soroban_sdk::BytesN<32>) {
        env.storage()
            .instance()
            .set(&KEY_WASM, &new_code_hash);
    }

    /// Non-conventional name 'reassign_authority' writes an address to KEY_ADMIN with no require_auth.
    pub fn reassign_authority(env: Env, new_authority: Address) {
        env.storage().instance().set(&KEY_ADMIN, &new_authority);
    }

    /// Non-conventional name, has structural signals, but gated with require_auth.
    pub fn apply_patch(env: Env, new_code_hash: soroban_sdk::BytesN<32>) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_WASM, &new_code_hash);
    }
}
