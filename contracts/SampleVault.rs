//! Sample Soroban smart contract used as a scan target for AuditPulse.
//!
//! This contract intentionally contains patterns flagged by the scanner
//! (missing `require_auth`, `.unwrap()`, missing `extend_ttl`) so it can serve as
//! a demo input: `npx ts-node src/index.ts contracts/SampleVault.rs`.
//!
//! In addition to the original demo functions, this file now includes a small
//! set of utilities that exercise **temporary vs. persistent storage** TTL
//! (time‑to‑live) edge‑cases.  These helpers are useful for the new test fixtures
//! that verify the scanner’s ability to detect missing or incorrect TTL
//! extensions.
//!
//! The public API is deliberately minimal – the functions are only meant to be
//! called from unit‑tests (see the `#[cfg(test)]` module at the bottom of the
//! file).  Production contracts should expose a richer, permission‑checked
//! interface.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, Symbol, String,
};

#[cfg(test)]
use soroban_sdk::testutils::LedgerInfo;

/// Keys used to store contract‑wide data.
#[contracttype]
pub struct DataKey {
    pub admin: Symbol,
    pub balances: Symbol,
}

/// The main contract struct.
#[contract]
pub struct SampleVault;

#[contractimpl]
impl SampleVault {
    // -------------------------------------------------------------------------
    // Original demo functions (unchanged)
    // -------------------------------------------------------------------------

    /// Intentionally missing `require_auth`: flagged by the scanner.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Intentionally using `unwrap()`: flagged by the scanner.
    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey {
                admin: Symbol::new(&env, "admin"),
                balances: Symbol::new(&env, "balances"),
            })
            .unwrap()
    }

    /// Properly protected function: not flagged.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.require_auth(&from);
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&from, &env.current_contract_address(), &amount);
        let entry = env.storage().persistent();
        // The scanner looks for calls to `extend_ttl`. This is a correct usage.
        entry.extend_ttl(&Self::key(&env), 100, 200);
    }

    // -------------------------------------------------------------------------
    // New helpers for TTL / expiration edge‑case testing
    // -------------------------------------------------------------------------

    /// Store a temporary value with an explicit TTL (in seconds).
    ///
    /// * `key` – Symbol that identifies the entry.
    /// * `value` – `i128` value to store.
    /// * `ttl_seconds` – Desired TTL; a value of `0` means “expire immediately”.
    pub fn set_temp_data(env: Env, key: Symbol, value: i128, ttl_seconds: u32) {
        // Temporary storage is automatically scoped to the current ledger
        // entry, but we can force a TTL for testing purposes.
        let entry = env.storage().temporary();
        entry.set(&key, &value);
        // `extend_ttl` works for temporary entries as well. Using `0` is an
        // edge case that should result in immediate expiration.
        entry.extend_ttl(&key, ttl_seconds, 0);
    }

    /// Retrieve a temporary value.
    ///
    /// Returns `None` if the key does not exist or has already expired.
    pub fn get_temp_data(env: Env, key: Symbol) -> Option<i128> {
        env.storage().temporary().get(&key)
    }

    /// Attempt to extend the TTL of a *temporary* entry.
    ///
    /// Returns `true` if the key existed and the TTL was updated,
    /// `false` otherwise (e.g., the key is missing or already expired).
    pub fn extend_temp_ttl(env: Env, key: Symbol, add_seconds: u32) -> bool {
        let entry = env.storage().temporary();
        if entry.has(&key) {
            entry.extend_ttl(&key, add_seconds, 0);
            true
        } else {
            false
        }
    }

    /// Store a *persistent* value with an explicit TTL and rent‑charge.
    ///
    /// * `ttl_seconds` – How long the entry should stay alive.
    /// * `rent` – Rent units to charge; `0` is allowed but atypical.
    pub fn set_persistent_with_ttl(
        env: Env,
        key: Symbol,
        value: i128,
        ttl_seconds: u32,
        rent: u32,
    ) {
        let entry = env.storage().persistent();
        entry.set(&key, &value);
        entry.extend_ttl(&key, ttl_seconds, rent);
    }

    /// Explicitly delete a persistent entry. This is useful for testing
    /// expiration behaviour without waiting for the TTL to lapse.
    pub fn delete_persistent(env: Env, key: Symbol) {
        env.storage().persistent().remove(&key);
    }

    // -------------------------------------------------------------------------
    // Private helpers (unchanged)
    // -------------------------------------------------------------------------

    fn token_id(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .unwrap_or_else(|| panic!("token not set"))
    }

    fn key(env: &Env) -> Symbol {
        Symbol::new(env, "balances")
    }
}

// -----------------------------------------------------------------------------
// Helper stub used by the scanner demo (kept unchanged)
// -----------------------------------------------------------------------------
fn placeholder(_: String) -> i128 {
    0
}

// -----------------------------------------------------------------------------
// Unit‑tests for the new TTL helpers (compiled only in test mode)
// -----------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{Env, Symbol};

    /// Helper to create a fresh mock environment with deterministic auth.
    fn mock_env() -> Env {
        let env = Env::default();
        // By default the mock environment authorises every address, which is
        // sufficient for these storage‑centric tests.
        env.mock_all_auths();
        env
    }

    #[test]
    fn temp_set_and_get_basic() {
        let env = mock_env();
        let key = Symbol::short("temp_key");
        SampleVault::set_temp_data(env.clone(), key.clone(), 42, 10);
        assert_eq!(SampleVault::get_temp_data(env.clone(), key.clone()), Some(42));
    }

    #[test]
    fn temp_ttl_zero_expires_immediately() {
        let env = mock_env();
        let key = Symbol::short("zero_ttl");
        // TTL = 0 → entry should be considered expired right away.
        SampleVault::set_temp_data(env.clone(), key.clone(), 99, 0);
        // Even without advancing the ledger, `get_temp_data` must return None.
        assert_eq!(SampleVault::get_temp_data(env.clone(), key.clone()), None);
    }

    #[test]
    fn extend_nonexistent_temp_key_returns_false() {
        let env = mock_env();
        let key = Symbol::short("no_such_key");
        let result = SampleVault::extend_temp_ttl(env.clone(), key.clone(), 5);
        assert!(!result, "extend should fail for missing key");
    }

    #[test]
    fn persistent_ttl_extension_and_manual_deletion() {
        let env = mock_env();
        let key = Symbol::short("persist_key");
        SampleVault::set_persistent_with_ttl(env.clone(), key.clone(), 12345, 30, 10);
        // Verify the value is present immediately.
        let stored: Option<i128> = env.storage().persistent().get(&key);
        assert_eq!(stored, Some(12345));

        // Manually delete and ensure it's gone.
        SampleVault::delete_persistent(env.clone(), key.clone());
        let after_delete: Option<i128> = env.storage().persistent().get(&key);
        assert_eq!(after_delete, None);
    }

    #[test]
    fn persistent_ttl_zero_behaviour() {
        let env = mock_env();
        let key = Symbol::short("persist_zero");
        // A TTL of zero should mark the entry as expired instantly.
        SampleVault::set_persistent_with_ttl(env.clone(), key.clone(), 777, 0, 0);
        // The entry is still retrievable in the same ledger round because the
        // mock env does not auto‑purge; however, advancing the ledger should
        // remove it.
        env.ledger().set(LedgerInfo {
            timestamp: 1,
            protocol_version: 0,
            base_reserve: 0,
            network_id: Default::default(),
            sequence_number: 1,
            ..Default::default()
        });
        let after_advance: Option<i128> = env.storage().persistent().get(&key);
        assert_eq!(after_advance, None);
    }
}