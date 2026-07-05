//! ALICE-Auth: Ed25519 ZKP Authentication.
//!
//! Zero-allocation, branchless Ed25519 challenge-response authentication.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::module_name_repetitions,
    clippy::inline_always,
    clippy::too_many_lines,
    clippy::wildcard_imports,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::missing_safety_doc,
    clippy::return_self_not_must_use,
    clippy::redundant_pub_crate,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::missing_const_for_fn,
    clippy::single_match_else,
    clippy::unused_self,
    clippy::unnecessary_map_or,
    clippy::option_if_let_else,
    clippy::unsafe_derive_deserialize,
    clippy::branches_sharing_code,
    clippy::useless_conversion,
    clippy::redundant_closure_for_method_calls,
    clippy::match_same_arms,
    clippy::float_cmp,
    clippy::trivially_copy_pass_by_ref,
    clippy::use_self,
    clippy::significant_drop_tightening,
    clippy::assigning_clones,
    clippy::or_fun_call,
    clippy::inline_always,
    clippy::doc_link_with_quotes,
    clippy::too_many_arguments,
    clippy::duplicated_attributes,
    clippy::manual_let_else
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod challenge_ttl;
pub mod ct;
pub mod errors;
pub mod hex;
pub mod identity;
pub mod key_rotation;
pub mod prelude;
pub mod protocol;
pub mod random;
pub mod social_recovery;
pub mod trust_chain;
pub mod types;
pub mod verify;

#[cfg(feature = "crypto")]
pub mod crypto_bridge;

#[cfg(feature = "std")]
pub mod jwt;

#[cfg(feature = "nizk")]
pub mod nizk;

#[cfg(feature = "std")]
pub mod totp;

#[cfg(feature = "db")]
pub mod db_bridge;

#[cfg(feature = "api")]
pub mod api_bridge;

#[cfg(feature = "pyo3")]
pub mod python;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(all(feature = "ffi", feature = "nizk"))]
pub mod ffi_nizk;

#[cfg(all(feature = "ffi", feature = "crypto"))]
pub mod ffi_crypto;

#[cfg(all(test, feature = "std"))]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::challenge_ttl::*;
pub use crate::ct::*;
pub use crate::errors::*;
pub use crate::identity::*;
pub use crate::key_rotation::*;
pub use crate::protocol::*;
pub use crate::random::*;
pub use crate::social_recovery::*;
pub use crate::trust_chain::*;
pub use crate::types::*;
pub use crate::verify::*;

#[cfg(feature = "ffi")]
pub use crate::ffi::*;

#[cfg(all(feature = "ffi", feature = "nizk"))]
pub use crate::ffi_nizk::*;

#[cfg(all(feature = "ffi", feature = "crypto"))]
pub use crate::ffi_crypto::*;

// no_std panic handler
#[cfg(all(not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
