//! Edge case: one function keeps its entry alive and another forgets to.
//! The rule is intentionally file-level — a single bump anywhere silences
//! the whole file — so this fixture pins that contract explicitly. A future
//! per-function granularity change must update this expectation
//! deliberately instead of silently flipping it.
//!
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct MixedTtl;

#[contractimpl]
impl MixedTtl {
    pub fn refresh(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage().persistent().set(&user, &true);
        env.storage().persistent().extend_ttl(&user, 100, 200);
    }

    pub fn forgetful(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage().persistent().set(&user, &false);
    }
}
