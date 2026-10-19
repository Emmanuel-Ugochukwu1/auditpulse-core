//! Clean Soroban contract demonstrating proper TTL management on both
//! persistent and temporary storage tiers.
//! Expected findings: 0.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlStorageCiManaged;

#[contractimpl]
impl TtlStorageCiManaged {
    /// Writes to persistent storage and immediately extends its TTL.
    pub fn save_persistent(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&user, &amount);
        env.storage().persistent().extend_ttl(&user, 500, 1000);
    }

    /// Writes to temporary storage and extends TTL using extend_ttl.
    pub fn save_temporary(env: Env, session_user: Address, session_id: Symbol, val: i128) {
        session_user.require_auth();
        env.storage().temporary().set(&session_id, &val);
        env.storage().temporary().extend_ttl(&session_id, 100, 200);
    }

    /// Safe read returning an Option instead of panicking with .unwrap().
    pub fn load_persistent(env: Env, user: Address) -> Option<i128> {
        env.storage().persistent().get(&user)
    }
}
