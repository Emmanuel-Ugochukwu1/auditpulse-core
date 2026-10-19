//! Safe fixture: functions with non-conventional upgrade/admin names
//! that exhibit structural signals (BytesN<32> wasm hashes, admin storage keys,
//! deployer updates) but are properly gated by require_auth.
//!
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct StructuralProtectedVault;

#[contractimpl]
impl StructuralProtectedVault {
    /// Non-conventional name 'commit_bytecode' writes a BytesN<32> wasm hash to storage,
    /// but is gated by the stored admin.
    pub fn commit_bytecode(env: Env, new_code_hash: soroban_sdk::BytesN<32>) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_WASM, &new_code_hash);
        env.storage().instance().extend_ttl(&KEY_WASM, 100, 200);
    }

    /// Non-conventional name 'reassign_authority' writes an address to KEY_ADMIN,
    /// but is gated by require_auth on the existing admin.
    pub fn reassign_authority(env: Env, new_authority: Address) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        admin.require_auth();
        env.storage().instance().set(&KEY_ADMIN, &new_authority);
        env.storage().instance().extend_ttl(&KEY_ADMIN, 100, 200);
    }

    /// Non-conventional name 'apply_patch' calls the deployer upgrade method,
    /// but is properly authorized by the admin.
    pub fn apply_patch(env: Env, new_code_hash: soroban_sdk::BytesN<32>) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        env.require_auth(&admin);
        env.deployer().update_current_contract_wasm(new_code_hash);
    }
}
