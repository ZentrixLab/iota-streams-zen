
#![allow(clippy::module_inception)]
#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]  
extern crate std;

/// Message definitions and utils for wrapping/unwrapping.
pub mod message;

/// Message addressing and linking
pub mod address;

/// Transport-related abstractions.
pub mod transport;

/// Identity-based Signature/Verification utilities
pub mod id; 

/// Errors specific for the crate
pub mod error;

// Export important items from submodules that are frequently used
pub use message::TransportMessage;
pub use address::Address;
pub use transport::Transport;


