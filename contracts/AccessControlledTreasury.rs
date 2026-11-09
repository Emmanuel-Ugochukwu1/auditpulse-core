//! Sample Soroban treasury whose authorization is injected by attribute
//! macros instead of being written in the function bodies, following the
//! OpenZeppelin Stellar contracts library (`stellar_macros`).
//!
//! What each macro expands to, at the very start of the function body:
//!
//! * `#[only_owner]` / `#[only_admin]`: load the stored owner/admin and call
//!   `require_auth()` on it.
//! * `#[only_role(account, "role")]` / `#[only_any_role(account, [..])]`:
//!   check role membership, then call `account.require_auth()`.
//! * `#[has_role(account, "role")]`: checks role membership ONLY. It does not
//!   call `require_auth()`, so the body has to; otherwise anyone can pass the
//!   address of a role holder.
//! * `#[when_not_paused]`: a pause guard, not an authorization check.
//!
//! Expected AuditPulse findings: only the two functions marked VULNERABLE.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env};
use stellar_access::access_control::AccessControl;
use stellar_access::ownable::Ownable;
use stellar_contract_utils::upgradeable::{self as upgradeable, Upgradeable};
use stellar_macros::{has_role, only_admin, only_any_role, only_owner, only_role, when_not_paused};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    TokenNotSet = 1,
}

#[contracttype]
pub enum DataKey {
    Token,
    FeeBps,
    Treasury,
}

const DAY_IN_LEDGERS: u32 = 17_280;
const TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const TTL_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    /// SAFE: the owner's authorization runs before the storage write.
    #[only_owner]
    pub fn set_fee(e: &Env, fee_bps: u32) {
        e.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        e.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// SAFE: the admin's authorization runs before the storage write.
    #[only_admin]
    pub fn set_token(e: &Env, token: Address) {
        e.storage().instance().set(&DataKey::Token, &token);
        e.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// SAFE: `caller` must hold the role and authorize the call.
    #[only_role(caller, "treasurer")]
    pub fn pay(e: &Env, to: Address, amount: i128, caller: Address) -> Result<(), Error> {
        let token: Address = e.storage().instance().get(&DataKey::Token).ok_or(Error::TokenNotSet)?;
        let client = token::Client::new(e, &token);
        client.transfer(&e.current_contract_address(), &to, &amount);
        Ok(())
    }

    /// SAFE: stacked attributes; the path-qualified role macro still
    /// requires `caller` to authorize the call.
    #[when_not_paused]
    #[stellar_macros::only_any_role(caller, ["treasurer", "operator"])]
    pub fn sweep(e: &Env, token: Address, to: Address, amount: i128, caller: Address) {
        let client = token::Client::new(e, &token);
        client.transfer(&e.current_contract_address(), &to, &amount);
    }

    /// SAFE: `#[has_role]` plus an explicit `require_auth()` in the body is
    /// the library's documented pattern for this macro.
    #[has_role(caller, "operator")]
    pub fn burn_fees(e: &Env, token: Address, amount: i128, caller: Address) {
        caller.require_auth();
        let client = token::Client::new(e, &token);
        client.burn(&e.current_contract_address(), &amount);
    }

    /// VULNERABLE: `#[has_role]` checks membership without authorization, so
    /// anyone can name a treasurer as `caller` and move funds.
    #[has_role(caller, "treasurer")]
    pub fn pay_unchecked(e: &Env, token: Address, to: Address, amount: i128, caller: Address) {
        let client = token::Client::new(e, &token);
        client.transfer(&e.current_contract_address(), &to, &amount);
    }

    /// VULNERABLE: a pause guard is not an authorization check.
    #[when_not_paused]
    pub fn set_treasury(e: &Env, treasury: Address) {
        e.storage().instance().set(&DataKey::Treasury, &treasury);
        e.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}

#[contractimpl]
impl Upgradeable for Treasury {
    /// SAFE: only an authorized "manager" can replace the contract code.
    #[only_role(operator, "manager")]
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, operator: Address) {
        upgradeable::upgrade(e, &new_wasm_hash);
    }
}

#[contractimpl(contracttrait)]
impl Ownable for Treasury {}

#[contractimpl(contracttrait)]
impl AccessControl for Treasury {}
