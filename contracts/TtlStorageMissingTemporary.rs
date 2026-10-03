use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct TtlStorageMissingTemporary;

#[contractimpl]
impl TtlStorageMissingTemporary {
    pub fn cache_without_refresh(env: Env, value: u32) {
        let temporary_key: Symbol = symbol_short!("temp");
        env.storage().temporary().set(&temporary_key, &value);
    }
}
