//! # Goblin signing
//!
//! Goblin signing is intended to be a support library for goblin to help with the signature of
//! executable.

pub mod errors;
pub mod authenticode;
pub mod certificate;
pub mod verify;
pub mod sign;
pub mod efi;
