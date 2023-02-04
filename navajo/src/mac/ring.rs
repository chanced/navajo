// use core::mem;
// use digest::{
//     core_api::{BlockSizeUser, CoreWrapper, CtVariableCoreWrapper},
//     generic_array::{typenum::*, GenericArray},
//     FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update,
// };
// use hmac::Hmac;
// use hmac::{HmacCore, Mac as CryptoMac};
// use paste::paste;
// use ring_compat::digest::{Sha256 as RingSha256, Sha384 as RingSha384, Sha512 as RingSha512};
// use ring_compat::ring;
// use ring_compat::ring::hmac::Context;
// macro_rules! impl_digest {
//     (
//         $(#[doc = $doc:tt])*
//         $name:ident, $hasher:ident, $block_len:ty, $output_size:ty
//     ) => {
// 		paste! {
// 			$(#[doc = $doc])*
// 			#[repr(transparent)]
// 			#[derive(Clone)]
// 			pub(super) struct $name([<Ring $name>]);

// 			// impl $name {
// 			// 	fn take(&mut self) -> Context {
// 			// 		self.0.reset()
// 			// 	}
// 			// }

// 			impl Default for $name {
// 				fn default() -> Self {
// 					$name([< Ring $name >]::default())
// 				}
// 			}

// 			impl Update for $name {
// 				fn update(&mut self, data: &[u8]) {
// 					self.0.update(data.as_ref())
// 				}
// 			}

// 			impl BlockSizeUser for $name {
// 				type BlockSize = $block_len;
// 			}

// 			impl OutputSizeUser for $name {
// 				type OutputSize = $output_size;
// 			}

// 			impl FixedOutput for $name {
// 				fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
// 					self.0.finalize_into(out)
// 				}
// 			}

// 			impl FixedOutputReset for $name {
// 				fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
// 					self.0.finalize_into_reset(out)
// 				}
// 			}

// 			impl Reset for $name {
// 				fn reset(&mut self) {
// 					self.0.reset()
// 				}
// 			}

// 			opaque_debug::implement!($name);
// 		}
// 	}
// }

// impl_digest!(
//     /// Structure representing the state of a SHA-256 computation
//     Sha256,
//     SHA256,
//     U64,
//     U32
// );

// impl_digest!(
//     /// Structure representing the state of a SHA-384 computation
//     Sha384,
//     SHA384,
//     U128,
//     U48
// );

// impl_digest!(
//     /// Structure representing the state of a SHA-512 computation
//     Sha512,
//     SHA512,
//     U128,
//     U64
// );
