use enum_dispatch::enum_dispatch;

use hmac::{Hmac, Mac};

// #[derive(Clone, Debug)]
pub struct Tag {
    // header: Header,
    // algo: Hash,
}

#[enum_dispatch]
pub(super) trait MacOutput {}

#[enum_dispatch(MacOuput)]
pub(super) enum Output {
    RingOutput,
    RustCryptoOutput,
}

pub(super) struct RingOutput {}
impl MacOutput for RingOutput {}

#[enum_dispatch]
pub(super) trait MacRustCryptoOutput {}

mod macros {}

macro_rules! rust_crypto_internal_tag {
    ($typ:ident, $typ_crt:ident, $crt:ident, $algo:ident$(, $cfg:tt)?) => {
        paste::paste! {
            #[cfg(all(feature="[< $typ:lower _ $algo>]"), $($cfg)?)]
            // #[derive(Clone, Debug)]
            pub(super) struct [< $typ $algo InternalTag >] (digest::CtOutput<$typ_crt::$typ<$crt::$algo>>);


            #[cfg(all(feature="[< $typ:lower _ $algo>]"), $($cfg)?)]
            impl MacRustCryptoOutput for [< $typ $algo InternalTag >] {

            }
        }
    };
}

macro_rules! rust_crypto_internal_tags {
    ({
        hmac: { ring: [$($ring:ident),*], sha2: [$($sha2:ident),*], sha3: [$($sha3:ident),*]$(,)? },
        cmac: { aes: [$($aes:ident),*]$(,)? }
	}) => {
        paste::paste! {
            #[enum_dispatch::enum_dispatch(MacRustCryptoOutput)]
            // #[derive(Clone)]
            pub(super) enum RustCryptoOutput {
                $(
                    #[cfg(not(feature = "ring"))]
                    [< Hmac $ring InternalTag >],
                )*
                #[cfg(feature="sha2")]
                $(
                    [< Hmac hmac $sha2 InternalTag >],
                )*
                #[cfg(feature="sha3")]
                $(
                    [< Hmac $sha3 InternalTag >],
                )*
                $(
                    [< Cmac $aes InternalTag >],
                )*
            }
			$(
                rust_crypto_internal_tag!(Hmac, hmac, sha2, $ring, not(feature="ring"));
			)*
            $(
                rust_crypto_internal_tag!(Hmac, hmac, sha2, $sha2);
			)*
            $(
				rust_crypto_internal_tag!(Hmac, hmac, sha3, $sha3);
			)*
            $(
				rust_crypto_internal_tag!(Cmac, hmac, aes, $aes);
			)*
        }
    }
}

// todo: Move this invocation up to mac.rs or remove it entirely with handwritten types.
// The issue is that enum_dispatch does not support path based invokcations.
// Alternatively, the functionality of enum_dispatch could be replaced in the macro.
rust_crypto_internal_tags!({
    hmac: {
        ring: [ Sha256, Sha384, Sha512 ],
        sha2: [ Sha224 ], // those not supported by ring
        sha3: [ Sha3_224, Sha3_256, Sha3_384, Sha3_512 ],
    },
    cmac: {
        aes: [Aes128, Aes192, Aes256]
    }
});
