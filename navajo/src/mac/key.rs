use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use enum_dispatch::enum_dispatch;
use hmac::{Hmac, Mac};
use paste::paste;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

#[derive(Clone, Debug)]
pub(super) struct Key;

#[enum_dispatch]
pub(super) trait MacKey {}

macro_rules! key_types{
    ({
        hmac: [$($hmac:ident),*],
        cmac: [$($cmac:ident),*]$(,)?
    }) => {

        #[enum_dispatch(MacKey)]
        enum KeyInner {

        }

        paste!{
            $(
                pub(super) struct [<Hmac $hmac >](Hmac<$hmac>);
            )*
            $(
                pub(super) struct [<Cmac $cmac >](Cmac<$cmac>);
            )*
        }

    };
}

// TODO: these shouldn't be defined per mod
key_types!({
    hmac: [Sha224, Sha256, Sha384, Sha512, Sha3_224, Sha3_256, Sha3_384, Sha3_512],
    cmac: [Aes128, Aes192, Aes256]
});
