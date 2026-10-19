//! Sample Soroban smart contract used as a scan target for AuditPulse.
//!
//! This contract intentionally mixes temporary and persistent storage with
//! edge-case TTL handling: it writes short-lived session entries to
//! temporary storage and long-lived payout records to persistent storage,
//! but never bumps any entry's TTL. Both kinds of entries can therefore
//! expire silently and read back as `None`.
//!
//! Scan it with: `npx tsx src/index.ts contracts/TtlEdgeCases.rs`

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct TtlEdgeCases;

#[contractimpl]
impl TtlEdgeCases {
    /// Opens a session in temporary storage. Temporary entries live only
    /// for a short ledger window, so skipping extend_ttl here expires the
    /// session almost immediately.
    pub fn open_session(env: Env, user: Address, session: Symbol) {
        env.require_auth(&user);
        let store = env.storage().temporary();
        store.set(&session, &user);
    }

    /// Reads a session back. If the temporary entry already expired this
    /// returns None even though the caller just opened it.
    pub fn close_session(env: Env, session: Symbol) -> bool {
        let store = env.storage().temporary();
        if store.has(&session) {
            store.remove(&session);
            true
        } else {
            false
        }
    }

    /// Writes a payout record to persistent storage without any
    /// extend_ttl. Persistent entries outlive temporary ones but still
    /// expire once their TTL runs out.
    pub fn record_payout(env: Env, id: Symbol, amount: i128) {
        let store = env.storage().persistent();
        let current: i128 = store.get(&id).unwrap_or(0);
        store.set(&id, &(current + amount));
    }

    /// Edge case: the read is gated behind nested conditions, so an
    /// expired entry surfaces as a skipped payout rather than an error,
    /// which is exactly the silent-expiry failure mode AP-STORAGE-001
    /// warns about.
    pub fn claim(env: Env, id: Symbol, min_amount: i128) -> i128 {
        let store = env.storage().persistent();
        if min_amount > 0 {
            if let Some(amount) = store.get::<Symbol, i128>(&id) {
                if amount >= min_amount {
                    store.remove(&id);
                    return amount;
                }
            }
        }
        0
    }
}
