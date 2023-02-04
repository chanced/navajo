use super::{key::Key, InternalTag};
use crate::error::MacError;
use alloc::sync::Arc;
use cfg_if::cfg_if;
use cmac::Cmac;
use enum_dispatch::enum_dispatch;
use hmac::{Hmac, Mac};

use paste::paste;
cfg_if! {
    if #[cfg(feature = "ring")] {
        use ring_compat::ring::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
    } else {
        use sha2::{Sha256, Sha384, Sha512};
    }

}
use sha2::{Sha256, Sha384, Sha512};

use aes::{Aes128, Aes192, Aes256};
use sha2::Sha224;
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

pub(super) struct Context(ContextInner);

#[enum_dispatch]
enum ContextInner {
    #[cfg(feature = "ring")]
    RingContext,
    RustCryptoContext,
}

#[enum_dispatch(ContextInner)]
trait MacContext {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> InternalTag;
}

#[cfg(feature = "ring")]
struct RingContext {}

impl MacContext for RingContext {
    fn update(&mut self, data: &[u8]) {
        unimplemented!()
    }
    fn finalize(self) -> InternalTag {
        unimplemented!()
    }
}

impl MacContext for RustCryptoContext {
    fn update(&mut self, data: &[u8]) {
        unimplemented!()
    }
    fn finalize(self) -> InternalTag {
        unimplemented!()
    }
}

macro_rules! rust_crypto_contexts {
    ({
        hmac: ([$($hmac_ring:ident),*], [$($hmac_rc:ident),*],),
        cmac: [$($cmac:ident),*]
	}) => {
        paste! {
			$(
				#[cfg(not(feature = "ring"))]
				#[derive(Clone, Debug)]
				struct [<Hmac $hmac_ring >] (Hmac<[< $hmac_ring >]>);

				#[cfg(not(feature = "ring"))]
				impl MacContext for [<Hmac $hmac_ring Context>] {
					fn update(&mut self, data: &[u8]) {
						todo!()
					}
					fn finalize(self) -> Tag {
						todo!()
					}
				}
			)*

			$(
				#[derive(Clone, Debug)]
				struct [<Hmac $hmac_rc Context>] (Hmac<[< $hmac_rc >]>);

				impl MacContext for [<Hmac $hmac_rc Context>] {
					fn update(&mut self, data: &[u8]) {
						todo!()
					}
					fn finalize(self) -> InternalTag {
						todo!()
					}
				}

			)*
			$(
				#[derive(Clone, Debug)]
				struct [<Cmac $cmac Context>] (Cmac<[< $cmac >]>);
				impl MacContext for [<Cmac $cmac Context>] {
					fn update(&mut self, data: &[u8]) {
						unimplemented!()
					}
					fn finalize(self) -> InternalTag {
						unimplemented!()
					}
				}
			)*

			#[derive(Clone, Debug)]
			enum RustCryptoContextInner {
				$(
					#[cfg(not(feature = "ring"))]
					[<Hmac $hmac_ring>]([<Hmac $hmac_ring Context>]),
				)*
				$(
					[<Hmac $hmac_rc>]([<Hmac $hmac_rc Context>]),
				)*
				$(
					[<Cmac $cmac>]([<Cmac $cmac Context>]),
				)*
			}
			impl MacContext for RustCryptoContextInner {
				cfg_if! {
					if #[cfg(feature = "ring")] {
						fn update(&mut self, data: &[u8]) {
							match self {
								$(
									Self::[<Hmac $hmac_rc>](ctx) => ctx.update(data),
								)*
								$(
									Self::[<Cmac $cmac>](ctx) => ctx.update(data),
								)*
							}
						}
						fn finalize(self) -> InternalTag {
							match self {
								$(
									Self::[<Hmac $hmac_rc>](ctx) => ctx.finalize(),
								)*
								$(
									Self::[<Cmac $cmac>](ctx) => ctx.finalize(),
								)*
							}
						}
					} else {
						fn update(&mut self, data: &[u8]) {
							match self {
								$(
									[<Hmac $hmac_ring>](ctx) => ctx.update(data),
								)*
								$(
									[<Hmac $hmac_rc>](ctx) => ctx.update(data),
								)*
								$(
									[<Cmac $cmac>](ctx) => ctx.update(data),
								)*
							}
						}
						fn finalize(self) -> Tag {
							match self {
								$(
									[<Hmac $hmac_ring>](ctx) => ctx.finalize(),
								)*
								$(
									[<Hmac $hmac_rc>](ctx) => ctx.finalize(),
								)*
								$(
									[<Cmac $cmac>](ctx) => ctx.finalize(),
								)*
							}
						}
					}
				}
			}
		}
	}
}
enum RustCryptoContext {}

rust_crypto_contexts!({
    hmac:  (
        [ Sha256, Sha384, Sha512 ],
        [Sha224, Sha3_224, Sha3_256, Sha3_384, Sha3_512],
    ),
    cmac: [Aes128, Aes192, Aes256]
});
