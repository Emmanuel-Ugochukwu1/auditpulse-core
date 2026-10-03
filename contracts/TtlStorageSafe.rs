use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

#[contract]
pub struct TtlStorageSafe;

#[contractimpl]
impl TtlStorageSafe {
    pub fn remember(env: Env, owner: Address, value: u32) {
        owner.require_auth();
        let persistent_key: Symbol = symbol_short!("persist");
        let temporary_key: Symbol = symbol_short!("temp");

        env.storage().persistent().set(&persistent_key, &value);
        env.storage().persistent().extend_ttl(&persistent_key, 100, 500);

        env.storage().temporary().set(&temporary_key, &value);
        env.storage().temporary().extend_ttl(&temporary_key, 20, 100);
    }

    pub fn refresh_existing(env: Env, owner: Address) {
        owner.require_auth();
        let persistent_key: Symbol = symbol_short!("persist");
        let temporary_key: Symbol = symbol_short!("temp");

        if env.storage().persistent().has(&persistent_key) {
            env.storage().persistent().extend_ttl(&persistent_key, 100, 500);
        }

        if env.storage().temporary().has(&temporary_key) {
            env.storage().temporary().extend_ttl(&temporary_key, 20, 100);
        }
    }
}
