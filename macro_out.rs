#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
extern crate alloc;
mod keyring {
    use serde::Deserialize;
    use serde::Serialize;
    pub(crate) const KEY_ID_LEN: usize = 4;
    #[serde(try_from = "i8", into = "i8")]
    #[repr(i8)]
    pub enum KeyStatus {
        /// Indicates that the key is active and the primary key in the keyring. It
        /// will be used, by default, for encryption.
        ///
        /// The key will be used for decryption when aplicable (i.e. ciphertext
        /// encrypted with it).
        Primary = 0,
        /// The indicates that the key is active and can be used for encryption if
        /// specified.
        ///
        /// The key will be used for decryption when applicable (i.e. ciphertext
        /// encrypted with it).
        Secondary = 1,
        /// Indicates that the key is disabled and cannot be used for encryption
        /// except for [daead] queries. It can still be used to decrypt applicable
        /// ciphertext.
        Disabled = -1,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for KeyStatus {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                KeyStatus::Primary => ::core::fmt::Formatter::write_str(f, "Primary"),
                KeyStatus::Secondary => ::core::fmt::Formatter::write_str(f, "Secondary"),
                KeyStatus::Disabled => ::core::fmt::Formatter::write_str(f, "Disabled"),
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for KeyStatus {
        #[inline]
        fn clone(&self) -> KeyStatus {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for KeyStatus {}
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for KeyStatus {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for KeyStatus {
        #[inline]
        fn eq(&self, other: &KeyStatus) -> bool {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            let __arg1_tag = ::core::intrinsics::discriminant_value(other);
            __self_tag == __arg1_tag
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for KeyStatus {}
    #[automatically_derived]
    impl ::core::cmp::Eq for KeyStatus {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {}
    }
    #[automatically_derived]
    impl ::core::hash::Hash for KeyStatus {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            ::core::hash::Hash::hash(&__self_tag, state)
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for KeyStatus {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serialize::serialize(
                    &_serde::__private::Into::<
                        i8,
                    >::into(_serde::__private::Clone::clone(self)),
                    __serializer,
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for KeyStatus {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                _serde::__private::Result::and_then(
                    <i8 as _serde::Deserialize>::deserialize(__deserializer),
                    |v| {
                        _serde::__private::TryFrom::try_from(v)
                            .map_err(_serde::de::Error::custom)
                    },
                )
            }
        }
    };
    impl Default for KeyStatus {
        fn default() -> Self {
            Self::Secondary
        }
    }
    impl KeyStatus {
        /// Returns `true` if `Primary`.
        pub fn is_primary(&self) -> bool {
            *self == Self::Primary
        }
        pub fn is_secondary(&self) -> bool {
            *self == Self::Secondary
        }
        /// Returns `true` if `Disabled`.
        pub fn is_disabled(&self) -> bool {
            match self {
                Self::Disabled => true,
                _ => false,
            }
        }
    }
    impl TryFrom<i8> for KeyStatus {
        type Error = String;
        fn try_from(i: i8) -> Result<Self, Self::Error> {
            match i {
                0 => Ok(Self::Primary),
                1 => Ok(Self::Secondary),
                -1 => Ok(Self::Disabled),
                _ => {
                    Err({
                        let res = ::alloc::fmt::format(
                            ::core::fmt::Arguments::new_v1(
                                &["invalid key status: "],
                                &[::core::fmt::ArgumentV1::new_display(&i)],
                            ),
                        );
                        res
                    })
                }
            }
        }
    }
    impl From<KeyStatus> for i8 {
        fn from(s: KeyStatus) -> Self {
            s as i8
        }
    }
    /// Metadata for a particular key.
    pub struct KeyInfo<A> {
        pub id: u32,
        pub algorithm: A,
        pub status: KeyStatus,
        pub created_at_timestamp: u64,
        /// The public key, if applicable.
        pub pub_key: Option<Vec<u8>>,
    }
    #[automatically_derived]
    impl<A: ::core::fmt::Debug> ::core::fmt::Debug for KeyInfo<A> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field5_finish(
                f,
                "KeyInfo",
                "id",
                &&self.id,
                "algorithm",
                &&self.algorithm,
                "status",
                &&self.status,
                "created_at_timestamp",
                &&self.created_at_timestamp,
                "pub_key",
                &&self.pub_key,
            )
        }
    }
    #[automatically_derived]
    impl<A: ::core::clone::Clone> ::core::clone::Clone for KeyInfo<A> {
        #[inline]
        fn clone(&self) -> KeyInfo<A> {
            KeyInfo {
                id: ::core::clone::Clone::clone(&self.id),
                algorithm: ::core::clone::Clone::clone(&self.algorithm),
                status: ::core::clone::Clone::clone(&self.status),
                created_at_timestamp: ::core::clone::Clone::clone(
                    &self.created_at_timestamp,
                ),
                pub_key: ::core::clone::Clone::clone(&self.pub_key),
            }
        }
    }
    #[automatically_derived]
    impl<A> ::core::marker::StructuralPartialEq for KeyInfo<A> {}
    #[automatically_derived]
    impl<A: ::core::cmp::PartialEq> ::core::cmp::PartialEq for KeyInfo<A> {
        #[inline]
        fn eq(&self, other: &KeyInfo<A>) -> bool {
            self.id == other.id && self.algorithm == other.algorithm
                && self.status == other.status
                && self.created_at_timestamp == other.created_at_timestamp
                && self.pub_key == other.pub_key
        }
    }
    #[automatically_derived]
    impl<A> ::core::marker::StructuralEq for KeyInfo<A> {}
    #[automatically_derived]
    impl<A: ::core::cmp::Eq> ::core::cmp::Eq for KeyInfo<A> {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<u32>;
            let _: ::core::cmp::AssertParamIsEq<A>;
            let _: ::core::cmp::AssertParamIsEq<KeyStatus>;
            let _: ::core::cmp::AssertParamIsEq<u64>;
            let _: ::core::cmp::AssertParamIsEq<Option<Vec<u8>>>;
        }
    }
    #[automatically_derived]
    impl<A: ::core::hash::Hash> ::core::hash::Hash for KeyInfo<A> {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            ::core::hash::Hash::hash(&self.id, state);
            ::core::hash::Hash::hash(&self.algorithm, state);
            ::core::hash::Hash::hash(&self.status, state);
            ::core::hash::Hash::hash(&self.created_at_timestamp, state);
            ::core::hash::Hash::hash(&self.pub_key, state)
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<A> _serde::Serialize for KeyInfo<A>
        where
            A: _serde::Serialize,
        {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "KeyInfo",
                    false as usize + 1 + 1 + 1 + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "id",
                    &self.id,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "algorithm",
                    &self.algorithm,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "status",
                    &self.status,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "created_at_timestamp",
                    &self.created_at_timestamp,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "pub_key",
                    &self.pub_key,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de, A> _serde::Deserialize<'de> for KeyInfo<A>
        where
            A: _serde::Deserialize<'de>,
        {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __field4,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            4u64 => _serde::__private::Ok(__Field::__field4),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "id" => _serde::__private::Ok(__Field::__field0),
                            "algorithm" => _serde::__private::Ok(__Field::__field1),
                            "status" => _serde::__private::Ok(__Field::__field2),
                            "created_at_timestamp" => {
                                _serde::__private::Ok(__Field::__field3)
                            }
                            "pub_key" => _serde::__private::Ok(__Field::__field4),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"id" => _serde::__private::Ok(__Field::__field0),
                            b"algorithm" => _serde::__private::Ok(__Field::__field1),
                            b"status" => _serde::__private::Ok(__Field::__field2),
                            b"created_at_timestamp" => {
                                _serde::__private::Ok(__Field::__field3)
                            }
                            b"pub_key" => _serde::__private::Ok(__Field::__field4),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de, A>
                where
                    A: _serde::Deserialize<'de>,
                {
                    marker: _serde::__private::PhantomData<KeyInfo<A>>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de, A> _serde::de::Visitor<'de> for __Visitor<'de, A>
                where
                    A: _serde::Deserialize<'de>,
                {
                    type Value = KeyInfo<A>;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct KeyInfo",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            u32,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct KeyInfo with 5 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            A,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct KeyInfo with 5 elements",
                                    ),
                                );
                            }
                        };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            KeyStatus,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        2usize,
                                        &"struct KeyInfo with 5 elements",
                                    ),
                                );
                            }
                        };
                        let __field3 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        3usize,
                                        &"struct KeyInfo with 5 elements",
                                    ),
                                );
                            }
                        };
                        let __field4 = match match _serde::de::SeqAccess::next_element::<
                            Option<Vec<u8>>,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        4usize,
                                        &"struct KeyInfo with 5 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(KeyInfo {
                            id: __field0,
                            algorithm: __field1,
                            status: __field2,
                            created_at_timestamp: __field3,
                            pub_key: __field4,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<u32> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<A> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<KeyStatus> = _serde::__private::None;
                        let mut __field3: _serde::__private::Option<u64> = _serde::__private::None;
                        let mut __field4: _serde::__private::Option<Option<Vec<u8>>> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u32>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "algorithm",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<A>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("status"),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            KeyStatus,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "created_at_timestamp",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field4 => {
                                    if _serde::__private::Option::is_some(&__field4) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "pub_key",
                                            ),
                                        );
                                    }
                                    __field4 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Option<Vec<u8>>,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("algorithm") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("status") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "created_at_timestamp",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field4 = match __field4 {
                            _serde::__private::Some(__field4) => __field4,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("pub_key") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(KeyInfo {
                            id: __field0,
                            algorithm: __field1,
                            status: __field2,
                            created_at_timestamp: __field3,
                            pub_key: __field4,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &[
                    "id",
                    "algorithm",
                    "status",
                    "created_at_timestamp",
                    "pub_key",
                ];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "KeyInfo",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<KeyInfo<A>>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
}
pub use keyring::*;
pub mod aead {}
pub mod error {
    use core::fmt;
    use std::{borrow::Cow, fmt::Display};
    pub use random::Error as RandError;
    #[cfg(feature = "ring")]
    use ring_compat::ring;
    pub struct KeyNotFoundError(pub u32);
    #[automatically_derived]
    impl ::core::fmt::Debug for KeyNotFoundError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "KeyNotFoundError",
                &&self.0,
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for KeyNotFoundError {
        #[inline]
        fn clone(&self) -> KeyNotFoundError {
            let _: ::core::clone::AssertParamIsClone<u32>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for KeyNotFoundError {}
    impl fmt::Display for KeyNotFoundError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(
                ::core::fmt::Arguments::new_v1(
                    &["missing key: "],
                    &[::core::fmt::ArgumentV1::new_display(&self.0)],
                ),
            )
        }
    }
    impl std::error::Error for KeyNotFoundError {}
    pub struct UnspecifiedError;
    #[automatically_derived]
    impl ::core::clone::Clone for UnspecifiedError {
        #[inline]
        fn clone(&self) -> UnspecifiedError {
            UnspecifiedError
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for UnspecifiedError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "UnspecifiedError")
        }
    }
    #[cfg(feature = "ring")]
    impl From<ring_compat::ring::error::Unspecified> for UnspecifiedError {
        fn from(_: ring_compat::ring::error::Unspecified) -> Self {
            Self
        }
    }
    impl fmt::Display for UnspecifiedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(::core::fmt::Arguments::new_v1(&["unspecified error"], &[]))
        }
    }
    impl std::error::Error for UnspecifiedError {}
    pub enum EncryptError {
        Unspecified,
        MissingPrimaryKey,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for EncryptError {
        #[inline]
        fn clone(&self) -> EncryptError {
            match self {
                EncryptError::Unspecified => EncryptError::Unspecified,
                EncryptError::MissingPrimaryKey => EncryptError::MissingPrimaryKey,
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for EncryptError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                EncryptError::Unspecified => {
                    ::core::fmt::Formatter::write_str(f, "Unspecified")
                }
                EncryptError::MissingPrimaryKey => {
                    ::core::fmt::Formatter::write_str(f, "MissingPrimaryKey")
                }
            }
        }
    }
    impl fmt::Display for EncryptError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
                Self::MissingPrimaryKey => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(&["missing primary key"], &[]),
                        )
                }
            }
        }
    }
    impl std::error::Error for EncryptError {}
    impl From<UnspecifiedError> for EncryptError {
        fn from(_: UnspecifiedError) -> Self {
            Self::Unspecified
        }
    }
    pub(crate) enum NonceSequenceError {
        CounterLimitExceeded,
        UnspecifiedError,
    }
    impl From<ring::error::Unspecified> for NonceSequenceError {
        fn from(_: ring::error::Unspecified) -> Self {
            Self::UnspecifiedError
        }
    }
    pub enum DecryptStreamError<E> {
        Unspecified,
        KeyNotFound(KeyNotFoundError),
        Malformed(MalformedError),
        Upstream(E),
    }
    #[automatically_derived]
    impl<E: ::core::fmt::Debug> ::core::fmt::Debug for DecryptStreamError<E> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                DecryptStreamError::Unspecified => {
                    ::core::fmt::Formatter::write_str(f, "Unspecified")
                }
                DecryptStreamError::KeyNotFound(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "KeyNotFound",
                        &__self_0,
                    )
                }
                DecryptStreamError::Malformed(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Malformed",
                        &__self_0,
                    )
                }
                DecryptStreamError::Upstream(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Upstream",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl<E> fmt::Display for DecryptStreamError<E>
    where
        E: std::error::Error,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                DecryptStreamError::Unspecified => {
                    fmt::Display::fmt(&UnspecifiedError, f)
                }
                DecryptStreamError::KeyNotFound(k) => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(
                                &["unknown key: "],
                                &[::core::fmt::ArgumentV1::new_display(&k)],
                            ),
                        )
                }
                DecryptStreamError::Malformed(e) => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(
                                &["malformed ciphertext: "],
                                &[::core::fmt::ArgumentV1::new_display(&e)],
                            ),
                        )
                }
                DecryptStreamError::Upstream(e) => fmt::Display::fmt(e, f),
            }
        }
    }
    impl<E> std::error::Error for DecryptStreamError<E>
    where
        E: std::error::Error,
    {}
    impl<E> From<DecryptError> for DecryptStreamError<E>
    where
        E: std::error::Error,
    {
        fn from(e: DecryptError) -> Self {
            match e {
                DecryptError::Unspecified => Self::Unspecified,
                DecryptError::KeyNotFound(k) => Self::KeyNotFound(k),
                DecryptError::Malformed(e) => Self::Malformed(e),
            }
        }
    }
    pub enum EncryptStreamError<E> {
        Unspecified,
        MissingPrimaryKey,
        CounterLimitExceeded,
        EmptyCleartext,
        Upstream(E),
    }
    #[automatically_derived]
    impl<E: ::core::fmt::Debug> ::core::fmt::Debug for EncryptStreamError<E> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                EncryptStreamError::Unspecified => {
                    ::core::fmt::Formatter::write_str(f, "Unspecified")
                }
                EncryptStreamError::MissingPrimaryKey => {
                    ::core::fmt::Formatter::write_str(f, "MissingPrimaryKey")
                }
                EncryptStreamError::CounterLimitExceeded => {
                    ::core::fmt::Formatter::write_str(f, "CounterLimitExceeded")
                }
                EncryptStreamError::EmptyCleartext => {
                    ::core::fmt::Formatter::write_str(f, "EmptyCleartext")
                }
                EncryptStreamError::Upstream(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Upstream",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl<E> From<UnspecifiedError> for DecryptStreamError<E> {
        fn from(_: UnspecifiedError) -> Self {
            Self::Unspecified
        }
    }
    impl<E> From<NonceSequenceError> for EncryptStreamError<E> {
        fn from(e: NonceSequenceError) -> Self {
            match e {
                NonceSequenceError::CounterLimitExceeded => Self::CounterLimitExceeded,
                NonceSequenceError::UnspecifiedError => Self::Unspecified,
            }
        }
    }
    impl<E> fmt::Display for EncryptStreamError<E>
    where
        E: std::error::Error,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
                Self::MissingPrimaryKey => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(&["missing primary key"], &[]),
                        )
                }
                Self::Upstream(e) => fmt::Display::fmt(e, f),
                Self::CounterLimitExceeded => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(
                                &["counter limit exceeded"],
                                &[],
                            ),
                        )
                }
                Self::EmptyCleartext => {
                    f
                        .write_fmt(
                            ::core::fmt::Arguments::new_v1(&["cleartext is empty"], &[]),
                        )
                }
            }
        }
    }
    impl<E> std::error::Error for EncryptStreamError<E>
    where
        E: std::error::Error,
    {}
    impl<E> From<UnspecifiedError> for EncryptStreamError<E> {
        fn from(e: UnspecifiedError) -> Self {
            Self::Unspecified
        }
    }
    pub enum DecryptError {
        /// The underlying cryptography library, *ring* returned an unspecified error.
        Unspecified,
        /// The keyset does not contain the key used to encrypt the ciphertext
        KeyNotFound(KeyNotFoundError),
        /// The ciphertext is malformed. See the opaque error message for details.
        Malformed(MalformedError),
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for DecryptError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                DecryptError::Unspecified => {
                    ::core::fmt::Formatter::write_str(f, "Unspecified")
                }
                DecryptError::KeyNotFound(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "KeyNotFound",
                        &__self_0,
                    )
                }
                DecryptError::Malformed(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Malformed",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for DecryptError {
        #[inline]
        fn clone(&self) -> DecryptError {
            match self {
                DecryptError::Unspecified => DecryptError::Unspecified,
                DecryptError::KeyNotFound(__self_0) => {
                    DecryptError::KeyNotFound(::core::clone::Clone::clone(__self_0))
                }
                DecryptError::Malformed(__self_0) => {
                    DecryptError::Malformed(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    impl From<KeyNotFoundError> for DecryptError {
        fn from(e: KeyNotFoundError) -> Self {
            Self::KeyNotFound(e)
        }
    }
    impl fmt::Display for DecryptError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
                Self::Malformed(e) => fmt::Display::fmt(e, f),
                Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
            }
        }
    }
    impl std::error::Error for DecryptError {}
    impl From<UnspecifiedError> for DecryptError {
        fn from(e: UnspecifiedError) -> Self {
            Self::Unspecified
        }
    }
    impl From<ring::error::Unspecified> for DecryptError {
        fn from(_: ring::error::Unspecified) -> Self {
            Self::Unspecified
        }
    }
    pub struct MalformedError(Cow<'static, str>);
    #[automatically_derived]
    impl ::core::fmt::Debug for MalformedError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "MalformedError",
                &&self.0,
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for MalformedError {
        #[inline]
        fn clone(&self) -> MalformedError {
            MalformedError(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<E> From<MalformedError> for DecryptStreamError<E> {
        fn from(e: MalformedError) -> Self {
            Self::Malformed(e)
        }
    }
    impl From<MalformedError> for DecryptError {
        fn from(e: MalformedError) -> Self {
            Self::Malformed(e)
        }
    }
    impl From<&'static str> for MalformedError {
        fn from(s: &'static str) -> Self {
            Self(Cow::Borrowed(s))
        }
    }
    impl From<String> for MalformedError {
        fn from(s: String) -> Self {
            Self(Cow::Owned(s))
        }
    }
    impl fmt::Display for MalformedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(
                ::core::fmt::Arguments::new_v1(
                    &["malformed ciphertext: "],
                    &[::core::fmt::ArgumentV1::new_display(&&self.0)],
                ),
            )
        }
    }
    impl std::error::Error for MalformedError {}
    pub(crate) enum HeaderError {
        Unspecified,
        Malformed(MalformedError),
        KeyNotFound(KeyNotFoundError),
    }
    pub struct InvalidAlgorithm(pub(crate) u8);
    #[automatically_derived]
    impl ::core::clone::Clone for InvalidAlgorithm {
        #[inline]
        fn clone(&self) -> InvalidAlgorithm {
            let _: ::core::clone::AssertParamIsClone<u8>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for InvalidAlgorithm {}
    #[automatically_derived]
    impl ::core::fmt::Debug for InvalidAlgorithm {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "InvalidAlgorithm",
                &&self.0,
            )
        }
    }
    impl fmt::Display for InvalidAlgorithm {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(
                ::core::fmt::Arguments::new_v1(
                    &["invalid algorithm: "],
                    &[::core::fmt::ArgumentV1::new_display(&self.0)],
                ),
            )
        }
    }
    impl std::error::Error for InvalidAlgorithm {}
    impl From<u8> for InvalidAlgorithm {
        fn from(v: u8) -> Self {
            Self(v)
        }
    }
    pub enum TruncationError {
        NotTruncatable,
        TooShort,
    }
    pub enum MacError {}
    pub struct InvalidKeyLength;
    #[automatically_derived]
    impl ::core::fmt::Debug for InvalidKeyLength {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "InvalidKeyLength")
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for InvalidKeyLength {
        #[inline]
        fn clone(&self) -> InvalidKeyLength {
            InvalidKeyLength
        }
    }
    impl Display for InvalidKeyLength {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(::core::fmt::Arguments::new_v1(&["invalid key length"], &[]))
        }
    }
    impl std::error::Error for InvalidKeyLength {}
    impl From<crypto_common::InvalidLength> for InvalidKeyLength {
        fn from(_: crypto_common::InvalidLength) -> Self {
            Self {}
        }
    }
}
mod id {
    use hashbrown::HashSet;
    use crate::error::UnspecifiedError;
    use crate::rand;
    pub(crate) fn gen_id() -> u32 {
        let mut data = [0; 4];
        rand::fill(&mut data);
        let mut value: u32 = u32::from_be_bytes(data);
        while value < 100_000_000 {
            rand::fill(&mut data);
            value = u32::from_be_bytes(data);
        }
        value
    }
    pub(crate) fn gen_unique_id(lookup: &HashSet<u32>) -> u32 {
        let mut id = gen_id();
        while lookup.contains(&id) {
            id = gen_id();
        }
        id
    }
}
pub(crate) use id::*;
mod rand {
    #[cfg(feature = "ring")]
    use ring_compat::ring::rand::{SecureRandom as _, SystemRandom};
    use random::{rngs::OsRng, CryptoRng, RngCore};
    #[cfg(feature = "ring")]
    pub(crate) fn fill(dst: &mut [u8]) {
        Random::fill(dst)
    }
    /// A random number generator that uses [*ring*'s `SystemRandom`](https://docs.rs/ring/0.16.20/ring/rand/struct.SystemRandom.html) if the `"ring"`
    /// feature is enabled, otherwise it uses [rand's `OsRng`](https://docs.rs/rand/0.8/rand/rngs/struct.OsRng.html).
    pub struct Random;
    #[cfg(feature = "ring")]
    impl CryptoRng for Random {}
    #[cfg(feature = "ring")]
    impl Random {
        pub fn new() -> Self {
            Self
        }
        pub fn fill(dst: &mut [u8]) {
            SystemRandom::new()
                .fill(dst)
                .unwrap_or_else(|_| {
                    OsRng.fill_bytes(dst);
                });
        }
    }
    #[cfg(feature = "ring")]
    impl RngCore for Random {
        fn next_u32(&mut self) -> u32 {
            let mut data = [0; 4];
            SystemRandom::new()
                .fill(&mut data)
                .ok()
                .map_or(OsRng.next_u32(), |_| u32::from_be_bytes(data))
        }
        fn next_u64(&mut self) -> u64 {
            let mut data = [0; 8];
            SystemRandom::new()
                .fill(&mut data)
                .ok()
                .map_or(OsRng.next_u64(), |_| u64::from_be_bytes(data))
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            SystemRandom::new().fill(dest).ok().map_or(OsRng.fill_bytes(dest), |_| ())
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), random::Error> {
            SystemRandom::new().fill(dest).or_else(|_| OsRng.try_fill_bytes(dest))
        }
    }
}
pub use rand::Random;
mod timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    pub(crate) fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
pub mod hkdf {
    pub enum Algorithm {
        HkdfSha256,
        HkdfSha384,
        HkdfSha512,
    }
}
pub mod mac {
    mod algorithm {
        use random::RngCore;
        use serde_repr::{Deserialize_repr, Serialize_repr};
        const SHA2_256_KEY_LEN: usize = 32;
        const SHA2_224_KEY_LEN: usize = 32;
        const SHA2_384_KEY_LEN: usize = 48;
        const SHA2_512_KEY_LEN: usize = 64;
        const SHA2_512_224_KEY_LEN: usize = 64;
        const SHA2_512_256_KEY_LEN: usize = 64;
        const SHA3_224_KEY_LEN: usize = 32;
        const SHA3_256_KEY_LEN: usize = 32;
        const SHA3_384_KEY_LEN: usize = 48;
        const SHA3_512_KEY_LEN: usize = 64;
        const BLAKE3_KEY_LEN: usize = 32;
        const AES128_KEY_LEN: usize = 16;
        const AES192_KEY_LEN: usize = 24;
        const AES256_KEY_LEN: usize = 32;
        #[repr(u8)]
        pub enum Algorithm {
            #[cfg(feature = "hmac_sha2")]
            Sha256 = 0,
            #[cfg(feature = "hmac_sha2")]
            Sha224 = 1,
            #[cfg(feature = "hmac_sha2")]
            Sha384 = 2,
            #[cfg(feature = "hmac_sha2")]
            Sha512 = 3,
            #[cfg(feature = "hmac_sha2")]
            Sha2_512_224 = 4,
            #[cfg(feature = "hmac_sha2")]
            Sha512_256 = 5,
            #[cfg(feature = "hmac_sha3")]
            Sha3_256 = 6,
            #[cfg(feature = "hmac_sha3")]
            Sha3_224 = 7,
            #[cfg(feature = "hmac_sha3")]
            Sha3_384 = 8,
            #[cfg(feature = "hmac_sha3")]
            Sha3_512 = 9,
            #[cfg(feature = "blake3")]
            Blake3 = 10,
            #[cfg(feature = "cmac_aes")]
            Aes128 = 128,
            #[cfg(feature = "cmac_aes")]
            Aes192 = 129,
            #[cfg(feature = "cmac_aes")]
            Aes256 = 130,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Algorithm {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    Algorithm::Sha256 => ::core::fmt::Formatter::write_str(f, "Sha256"),
                    Algorithm::Sha224 => ::core::fmt::Formatter::write_str(f, "Sha224"),
                    Algorithm::Sha384 => ::core::fmt::Formatter::write_str(f, "Sha384"),
                    Algorithm::Sha512 => ::core::fmt::Formatter::write_str(f, "Sha512"),
                    Algorithm::Sha2_512_224 => {
                        ::core::fmt::Formatter::write_str(f, "Sha2_512_224")
                    }
                    Algorithm::Sha512_256 => {
                        ::core::fmt::Formatter::write_str(f, "Sha512_256")
                    }
                    Algorithm::Sha3_256 => {
                        ::core::fmt::Formatter::write_str(f, "Sha3_256")
                    }
                    Algorithm::Sha3_224 => {
                        ::core::fmt::Formatter::write_str(f, "Sha3_224")
                    }
                    Algorithm::Sha3_384 => {
                        ::core::fmt::Formatter::write_str(f, "Sha3_384")
                    }
                    Algorithm::Sha3_512 => {
                        ::core::fmt::Formatter::write_str(f, "Sha3_512")
                    }
                    Algorithm::Blake3 => ::core::fmt::Formatter::write_str(f, "Blake3"),
                    Algorithm::Aes128 => ::core::fmt::Formatter::write_str(f, "Aes128"),
                    Algorithm::Aes192 => ::core::fmt::Formatter::write_str(f, "Aes192"),
                    Algorithm::Aes256 => ::core::fmt::Formatter::write_str(f, "Aes256"),
                }
            }
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Algorithm {
            #[inline]
            fn clone(&self) -> Algorithm {
                *self
            }
        }
        #[automatically_derived]
        impl ::core::marker::Copy for Algorithm {}
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Algorithm {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Algorithm {
            #[inline]
            fn eq(&self, other: &Algorithm) -> bool {
                let __self_tag = ::core::intrinsics::discriminant_value(self);
                let __arg1_tag = ::core::intrinsics::discriminant_value(other);
                __self_tag == __arg1_tag
            }
        }
        #[automatically_derived]
        impl ::core::marker::StructuralEq for Algorithm {}
        #[automatically_derived]
        impl ::core::cmp::Eq for Algorithm {
            #[inline]
            #[doc(hidden)]
            #[no_coverage]
            fn assert_receiver_is_total_eq(&self) -> () {}
        }
        #[automatically_derived]
        impl ::core::hash::Hash for Algorithm {
            fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
                let __self_tag = ::core::intrinsics::discriminant_value(self);
                ::core::hash::Hash::hash(&__self_tag, state)
            }
        }
        impl serde::Serialize for Algorithm {
            #[allow(clippy::use_self)]
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let value: u8 = match *self {
                    Algorithm::Sha256 => Algorithm::Sha256 as u8,
                    Algorithm::Sha224 => Algorithm::Sha224 as u8,
                    Algorithm::Sha384 => Algorithm::Sha384 as u8,
                    Algorithm::Sha512 => Algorithm::Sha512 as u8,
                    Algorithm::Sha2_512_224 => Algorithm::Sha2_512_224 as u8,
                    Algorithm::Sha512_256 => Algorithm::Sha512_256 as u8,
                    Algorithm::Sha3_256 => Algorithm::Sha3_256 as u8,
                    Algorithm::Sha3_224 => Algorithm::Sha3_224 as u8,
                    Algorithm::Sha3_384 => Algorithm::Sha3_384 as u8,
                    Algorithm::Sha3_512 => Algorithm::Sha3_512 as u8,
                    Algorithm::Blake3 => Algorithm::Blake3 as u8,
                    Algorithm::Aes128 => Algorithm::Aes128 as u8,
                    Algorithm::Aes192 => Algorithm::Aes192 as u8,
                    Algorithm::Aes256 => Algorithm::Aes256 as u8,
                };
                serde::Serialize::serialize(&value, serializer)
            }
        }
        impl<'de> serde::Deserialize<'de> for Algorithm {
            #[allow(clippy::use_self)]
            fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct discriminant;
                #[allow(non_upper_case_globals)]
                impl discriminant {
                    const Sha256: u8 = Algorithm::Sha256 as u8;
                    const Sha224: u8 = Algorithm::Sha224 as u8;
                    const Sha384: u8 = Algorithm::Sha384 as u8;
                    const Sha512: u8 = Algorithm::Sha512 as u8;
                    const Sha2_512_224: u8 = Algorithm::Sha2_512_224 as u8;
                    const Sha512_256: u8 = Algorithm::Sha512_256 as u8;
                    const Sha3_256: u8 = Algorithm::Sha3_256 as u8;
                    const Sha3_224: u8 = Algorithm::Sha3_224 as u8;
                    const Sha3_384: u8 = Algorithm::Sha3_384 as u8;
                    const Sha3_512: u8 = Algorithm::Sha3_512 as u8;
                    const Blake3: u8 = Algorithm::Blake3 as u8;
                    const Aes128: u8 = Algorithm::Aes128 as u8;
                    const Aes192: u8 = Algorithm::Aes192 as u8;
                    const Aes256: u8 = Algorithm::Aes256 as u8;
                }
                match <u8 as serde::Deserialize>::deserialize(deserializer)? {
                    discriminant::Sha256 => core::result::Result::Ok(Algorithm::Sha256),
                    discriminant::Sha224 => core::result::Result::Ok(Algorithm::Sha224),
                    discriminant::Sha384 => core::result::Result::Ok(Algorithm::Sha384),
                    discriminant::Sha512 => core::result::Result::Ok(Algorithm::Sha512),
                    discriminant::Sha2_512_224 => {
                        core::result::Result::Ok(Algorithm::Sha2_512_224)
                    }
                    discriminant::Sha512_256 => {
                        core::result::Result::Ok(Algorithm::Sha512_256)
                    }
                    discriminant::Sha3_256 => {
                        core::result::Result::Ok(Algorithm::Sha3_256)
                    }
                    discriminant::Sha3_224 => {
                        core::result::Result::Ok(Algorithm::Sha3_224)
                    }
                    discriminant::Sha3_384 => {
                        core::result::Result::Ok(Algorithm::Sha3_384)
                    }
                    discriminant::Sha3_512 => {
                        core::result::Result::Ok(Algorithm::Sha3_512)
                    }
                    discriminant::Blake3 => core::result::Result::Ok(Algorithm::Blake3),
                    discriminant::Aes128 => core::result::Result::Ok(Algorithm::Aes128),
                    discriminant::Aes192 => core::result::Result::Ok(Algorithm::Aes192),
                    discriminant::Aes256 => core::result::Result::Ok(Algorithm::Aes256),
                    other => {
                        core::result::Result::Err(
                            serde::de::Error::custom(
                                ::core::fmt::Arguments::new_v1(
                                    &[
                                        "invalid value: ",
                                        ", expected one of: ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                        ", ",
                                    ],
                                    &[
                                        ::core::fmt::ArgumentV1::new_display(&other),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Sha256),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Sha224),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Sha384),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Sha512),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha2_512_224,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha512_256,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha3_256,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha3_224,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha3_384,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(
                                            &discriminant::Sha3_512,
                                        ),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Blake3),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Aes128),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Aes192),
                                        ::core::fmt::ArgumentV1::new_display(&discriminant::Aes256),
                                    ],
                                ),
                            ),
                        )
                    }
                }
            }
        }
        impl Algorithm {
            pub(super) fn generate_key(&self) -> Vec<u8> {
                let mut key = ::alloc::vec::from_elem(0u8, self.default_key_len());
                crate::rand::fill(&mut key);
                key
            }
            pub fn default_key_len(&self) -> usize {
                match self {
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha256 => SHA2_256_KEY_LEN,
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha224 => SHA2_224_KEY_LEN,
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha384 => SHA2_384_KEY_LEN,
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha512 => SHA2_512_KEY_LEN,
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha2_512_224 => SHA2_512_224_KEY_LEN,
                    #[cfg(feature = "hmac_sha2")]
                    Algorithm::Sha512_256 => SHA2_512_256_KEY_LEN,
                    #[cfg(feature = "hmac_sha3")]
                    Algorithm::Sha3_256 => SHA3_256_KEY_LEN,
                    #[cfg(feature = "hmac_sha3")]
                    Algorithm::Sha3_224 => SHA3_224_KEY_LEN,
                    #[cfg(feature = "hmac_sha3")]
                    Algorithm::Sha3_384 => SHA3_384_KEY_LEN,
                    #[cfg(feature = "hmac_sha3")]
                    Algorithm::Sha3_512 => SHA3_512_KEY_LEN,
                    #[cfg(feature = "blake3")]
                    Algorithm::Blake3 => BLAKE3_KEY_LEN,
                    #[cfg(feature = "cmac_aes")]
                    Algorithm::Aes128 => AES128_KEY_LEN,
                    #[cfg(feature = "cmac_aes")]
                    Algorithm::Aes192 => AES192_KEY_LEN,
                    #[cfg(feature = "cmac_aes")]
                    Algorithm::Aes256 => AES256_KEY_LEN,
                }
            }
        }
    }
    mod context {
        use super::{key::MacKey, Output};
        #[allow(clippy::large_enum_variant)]
        pub(super) enum Context {
            #[cfg(feature = "blake3")]
            Blake3(crate::mac::Blake3Context),
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Ring(crate::mac::RingContext),
            RustCrypto(Box<crate::mac::RustCryptoContext>),
        }
        impl Context {
            pub(super) fn new(key: &MacKey) -> Context {
                match &key {
                    MacKey::Ring(key) => key.as_ref().into(),
                    MacKey::RustCrypto(key) => {
                        Context::RustCrypto(Box::new(key.as_ref().into()))
                    }
                    MacKey::Blake3(key) => key.as_ref().into(),
                }
            }
        }
        #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
        impl From<&ring_compat::ring::hmac::Key> for Context {
            fn from(key: &ring_compat::ring::hmac::Key) -> Self {
                Self::Ring(key.into())
            }
        }
        impl From<&blake3::Hasher> for Context {
            fn from(key: &blake3::Hasher) -> Self {
                Self::Blake3(key.into())
            }
        }
        pub(super) trait MacContext {
            fn update(&mut self, data: &[u8]);
            fn finalize(self) -> Output;
        }
        #[cfg(feature = "blake3")]
        pub(crate) struct Blake3Context(blake3::Hasher);
        #[automatically_derived]
        impl ::core::clone::Clone for Blake3Context {
            #[inline]
            fn clone(&self) -> Blake3Context {
                Blake3Context(::core::clone::Clone::clone(&self.0))
            }
        }
        impl From<&blake3::Hasher> for Blake3Context {
            fn from(hasher: &blake3::Hasher) -> Self {
                Self(hasher.clone())
            }
        }
        impl MacContext for Blake3Context {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            fn finalize(self) -> Output {
                Output::Blake3(self.0.finalize().into())
            }
        }
        pub(super) struct RingContext(ring_compat::ring::hmac::Context);
        impl MacContext for RingContext {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            fn finalize(self) -> Output {
                self.0.sign().into()
            }
        }
        impl From<&ring_compat::ring::hmac::Key> for RingContext {
            fn from(key: &ring_compat::ring::hmac::Key) -> Self {
                Self(ring_compat::ring::hmac::Context::with_key(key))
            }
        }
        pub(super) use rust_crypto_context_inner;
        pub(super) use rust_crypto_contexts;
    }
    mod hasher {
        use std::sync::Arc;
        use rayon::ThreadPool;
        use super::{context::Context, Key, Tag};
        pub(super) struct Hasher {
            keys: Vec<Arc<Key>>,
            primary_key: Arc<Key>,
            contexts: Vec<Context>,
        }
        impl Hasher {
            pub(super) fn new(primary_key: Arc<Key>, keys: Vec<Arc<Key>>) -> Self {
                let mut ctxs = Vec::with_capacity(keys.len());
                for key in &keys {
                    ctxs.push(Context::new(&key.inner));
                }
                Self {
                    keys,
                    primary_key,
                    contexts: ctxs,
                }
            }
        }
    }
    mod key {
        use crate::{error::InvalidKeyLength, KeyStatus};
        use super::{algorithm, Algorithm};
        pub(super) struct Key {
            pub(super) id: u32,
            pub(super) algorithm: Algorithm,
            pub(super) inner: MacKey,
            pub(super) prefix: Option<Vec<u8>>,
            pub(super) status: KeyStatus,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Key {
            #[inline]
            fn clone(&self) -> Key {
                Key {
                    id: ::core::clone::Clone::clone(&self.id),
                    algorithm: ::core::clone::Clone::clone(&self.algorithm),
                    inner: ::core::clone::Clone::clone(&self.inner),
                    prefix: ::core::clone::Clone::clone(&self.prefix),
                    status: ::core::clone::Clone::clone(&self.status),
                }
            }
        }
        impl PartialEq for Key {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id && self.algorithm == other.algorithm
            }
        }
        impl Key {
            pub(super) fn new(
                id: u64,
                algorithm: Algorithm,
                bytes: &[u8],
                prefix: Option<Vec<u8>>,
                status: KeyStatus,
            ) -> Self {
                ::core::panicking::panic("not yet implemented")
            }
            pub(super) fn prefix(&self) -> Option<&[u8]> {
                self.prefix.as_deref()
            }
        }
        pub(super) enum MacKey {
            #[cfg(all(feature = "ring"))]
            Ring(Box<ring_compat::ring::hmac::Key>),
            RustCrypto(Box<crate::mac::RustCryptoKey>),
            #[cfg(feature = "blake3")]
            Blake3(Box<blake3::Hasher>),
        }
        #[automatically_derived]
        impl ::core::clone::Clone for MacKey {
            #[inline]
            fn clone(&self) -> MacKey {
                match self {
                    MacKey::Ring(__self_0) => {
                        MacKey::Ring(::core::clone::Clone::clone(__self_0))
                    }
                    MacKey::RustCrypto(__self_0) => {
                        MacKey::RustCrypto(::core::clone::Clone::clone(__self_0))
                    }
                    MacKey::Blake3(__self_0) => {
                        MacKey::Blake3(::core::clone::Clone::clone(__self_0))
                    }
                }
            }
        }
        #[cfg(feature = "blake3")]
        impl From<blake3::Hasher> for MacKey {
            fn from(key: blake3::Hasher) -> Self {
                Self::Blake3(Box::new(key))
            }
        }
        impl MacKey {
            pub(super) fn new(
                algorithm: Algorithm,
                bytes: &[u8],
            ) -> Result<Self, InvalidKeyLength> {
                match algorithm {
                    #[cfg(all(feature = "ring"))]
                    Algorithm::Sha256 => {
                        Ok(
                            Self::Ring(
                                Box::new(
                                    ring_compat::ring::hmac::Key::new(
                                        ring_compat::ring::hmac::HMAC_SHA256,
                                        bytes,
                                    ),
                                ),
                            ),
                        )
                    }
                    #[cfg(all(feature = "ring"))]
                    Algorithm::Sha384 => {
                        Ok(
                            Self::Ring(
                                Box::new(
                                    ring_compat::ring::hmac::Key::new(
                                        ring_compat::ring::hmac::HMAC_SHA384,
                                        bytes,
                                    ),
                                ),
                            ),
                        )
                    }
                    #[cfg(all(feature = "ring"))]
                    Algorithm::Sha512 => {
                        Ok(
                            Self::Ring(
                                Box::new(
                                    ring_compat::ring::hmac::Key::new(
                                        ring_compat::ring::hmac::HMAC_SHA512,
                                        bytes,
                                    ),
                                ),
                            ),
                        )
                    }
                    #[cfg(feature = "blake3")]
                    Algorithm::Blake3 => {
                        Ok(
                            Self::Blake3(
                                Box::new(
                                    blake3::Hasher::new_keyed(
                                        bytes.try_into().map_err(|_| InvalidKeyLength)?,
                                    ),
                                ),
                            ),
                        )
                    }
                    _ => {
                        Ok(
                            Self::RustCrypto(
                                Box::new(crate::mac::RustCryptoKey::new(algorithm, bytes)?),
                            ),
                        )
                    }
                }
            }
        }
        pub(super) use rust_crypto_key;
        pub(super) use rust_crypto_keys;
        fn x() {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(b"my secret and secure key");
        }
    }
    mod sink {}
    mod tag {
        use alloc::sync::{Arc, Weak};
        /// Tags are used to verify the integrity of data. They are generated for each
        /// active key within the keyring at the point of computation. If new keys are
        /// added to the keyring, tags can be updated by calling
        /// [`update`](Self::update), [`read_update`](Self::read_update), or
        /// [`stream_update`](Self::stream_update).
        ///
        /// When a key is deleted from the keyring, the computed tag for that given key
        /// will no longer be evaluated. Note though that the computed data remains in
        /// memory. If the `Tag` is not updated after all keys have been deleted, all
        /// attempts to [`verify`](Self::verify) will fail, returning a
        /// [`MacError::NoTagsAvailabe`](crate::error::MacError).
        ///
        /// If the keyring is composed of a single key and that fact will not change
        /// through the life of the application, it will be more efficient to use the
        /// tag as bytes by calling [`truncate(size).as_bytes()`](Self::truncate),
        /// [`as_bytes`](Self::as_bytes) or [`as_ref`](Self::as_ref). and evaluating the
        /// tag directly with
        /// [`constant_time::verify_slices_are_equal`](crate::constant_time::verify_slices_are_equal).
        /// ## Examples
        pub struct Tag {
            entries: Vec<Arc<Entry>>,
            primary: Arc<Entry>,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Tag {
            #[inline]
            fn clone(&self) -> Tag {
                Tag {
                    entries: ::core::clone::Clone::clone(&self.entries),
                    primary: ::core::clone::Clone::clone(&self.primary),
                }
            }
        }
        struct Entry {
            key: Weak<super::Key>,
            output: Output,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Entry {
            #[inline]
            fn clone(&self) -> Entry {
                Entry {
                    key: ::core::clone::Clone::clone(&self.key),
                    output: ::core::clone::Clone::clone(&self.output),
                }
            }
        }
        impl Entry {
            pub(super) fn new(key: &Arc<super::Key>, output: Output) -> Self {
                Self {
                    key: Arc::downgrade(key),
                    output,
                }
            }
            pub(super) fn truncatable(&self) -> bool {
                self.output.truncatable()
            }
            pub(super) fn truncate(
                &self,
                len: usize,
            ) -> Result<TruncatedTag, TruncationError> {
                Ok(TruncatedTag {
                    tag: self.clone(),
                    len,
                })
            }
            pub fn verify(&self, other: &[u8]) -> Result<(), MacError> {
                ::core::panicking::panic("not yet implemented")
            }
        }
        impl AsRef<[u8]> for Entry {
            fn as_ref(&self) -> &[u8] {
                self.output.as_ref()
            }
        }
        pub struct TruncatedTag {
            tag: Entry,
            len: usize,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for TruncatedTag {
            #[inline]
            fn clone(&self) -> TruncatedTag {
                TruncatedTag {
                    tag: ::core::clone::Clone::clone(&self.tag),
                    len: ::core::clone::Clone::clone(&self.len),
                }
            }
        }
        impl AsRef<[u8]> for TruncatedTag {
            fn as_ref(&self) -> &[u8] {
                &self.tag.as_ref()[..self.len]
            }
        }
        pub(super) trait DigestOutput: AsRef<[u8]> + Clone {
            fn into_bytes(self) -> Vec<u8> {
                self.as_ref().to_vec()
            }
            fn truncatable(&self) -> bool;
        }
        pub(super) enum Output {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Ring(RingOutput),
            RustCrypto(crate::mac::RustCryptoOutput),
            #[cfg(feature = "blake3")]
            Blake3(Blake3Output),
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Output {
            #[inline]
            fn clone(&self) -> Output {
                match self {
                    Output::Ring(__self_0) => {
                        Output::Ring(::core::clone::Clone::clone(__self_0))
                    }
                    Output::RustCrypto(__self_0) => {
                        Output::RustCrypto(::core::clone::Clone::clone(__self_0))
                    }
                    Output::Blake3(__self_0) => {
                        Output::Blake3(::core::clone::Clone::clone(__self_0))
                    }
                }
            }
        }
        impl DigestOutput for Output {
            fn truncatable(&self) -> bool {
                match self {
                    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
                    Self::Ring(output) => output.truncatable(),
                    Self::RustCrypto(output) => output.truncatable(),
                    Self::Blake3(output) => output.truncatable(),
                }
            }
        }
        impl AsRef<[u8]> for Output {
            fn as_ref(&self) -> &[u8] {
                match self {
                    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
                    Self::Ring(output) => output.as_ref(),
                    Self::RustCrypto(output) => output.as_ref(),
                    Self::Blake3(output) => output.as_ref(),
                }
            }
        }
        pub(super) struct RingOutput(ring_compat::ring::hmac::Tag);
        #[automatically_derived]
        impl ::core::clone::Clone for RingOutput {
            #[inline]
            fn clone(&self) -> RingOutput {
                RingOutput(::core::clone::Clone::clone(&self.0))
            }
        }
        impl AsRef<[u8]> for RingOutput {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
        impl DigestOutput for RingOutput {
            fn truncatable(&self) -> bool {
                true
            }
        }
        impl From<ring_compat::ring::hmac::Tag> for Output {
            fn from(output: ring_compat::ring::hmac::Tag) -> Self {
                Self::Ring(RingOutput(output))
            }
        }
        pub(super) struct Blake3Output(blake3::Hash);
        #[automatically_derived]
        impl ::core::clone::Clone for Blake3Output {
            #[inline]
            fn clone(&self) -> Blake3Output {
                Blake3Output(::core::clone::Clone::clone(&self.0))
            }
        }
        impl DigestOutput for Blake3Output {
            fn truncatable(&self) -> bool {
                true
            }
        }
        impl From<blake3::Hash> for Blake3Output {
            fn from(hash: blake3::Hash) -> Self {
                Self(hash)
            }
        }
        impl AsRef<[u8]> for Blake3Output {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
        impl From<Blake3Output> for Output {
            fn from(output: Blake3Output) -> Self {
                Self::Blake3(output)
            }
        }
        pub(super) use rust_crypto_internal_tag;
        pub(super) use rust_crypto_internal_tags;
        use crate::error::{MacError, TruncationError};
    }
    use std::sync::Arc;
    pub use algorithm::Algorithm;
    pub use tag::Tag;
    use context::*;
    use key::*;
    use tag::*;
    use crate::{error::InvalidKeyLength, KeyStatus};
    pub struct Mac {
        keys: Vec<Arc<Key>>,
        primary_key: Arc<Key>,
        primary_key_id: u32,
    }
    impl Mac {
        /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
        /// as the primary.
        pub fn new(algorithm: Algorithm) -> Result<Self, InvalidKeyLength> {
            let bytes = algorithm.generate_key();
            let id = crate::id::gen_id();
            let inner = MacKey::new(algorithm, &bytes)?;
            let key = Arc::new(Key {
                id,
                prefix: None,
                algorithm,
                inner,
                status: KeyStatus::Primary,
            });
            Ok(Self {
                keys: <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new([key.clone()]),
                ),
                primary_key: key,
                primary_key_id: id,
            })
        }
        /// Create a new MAC keyring by initializing it with the given key data as
        /// primary.
        ///
        /// If the key has a prefix, such as Tink's 5 bytes, it should be trimmed
        /// from `key` and passed as `prefix`.
        pub fn new_with_external_key(
            key: &[u8],
            algorithm: Algorithm,
            prefix: Option<&[u8]>,
        ) -> Result<Self, InvalidKeyLength> {
            let id = crate::id::gen_id();
            let inner = MacKey::new(algorithm, key)?;
            let prefix = prefix.map(|p| p.to_vec());
            let key = Arc::new(Key {
                id,
                prefix,
                algorithm,
                inner,
                status: KeyStatus::Primary,
            });
            Ok(Self {
                keys: <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new([key.clone()]),
                ),
                primary_key: key,
                primary_key_id: id,
            })
        }
        pub fn add_generated_key(
            &mut self,
            algorithm: Algorithm,
        ) -> Result<(), InvalidKeyLength> {
            let bytes = algorithm.generate_key();
            self.create_key(algorithm, &bytes, None)
        }
        pub fn add_external_key(
            &mut self,
            key: &[u8],
            algorithm: Algorithm,
            prefix: Option<&[u8]>,
        ) -> Result<(), InvalidKeyLength> {
            self.create_key(algorithm, key, prefix)
        }
        fn create_key(
            &mut self,
            algorithm: Algorithm,
            bytes: &[u8],
            prefix: Option<&[u8]>,
        ) -> Result<(), InvalidKeyLength> {
            let mut ids = hashbrown::HashSet::with_capacity(self.keys.len());
            for key in &self.keys {
                ids.insert(key.id);
            }
            let inner = MacKey::new(algorithm, bytes)?;
            let id = crate::id::gen_unique_id(&ids);
            self.keys
                .push(
                    Arc::new(Key {
                        id,
                        prefix: prefix.map(|p| p.to_vec()),
                        algorithm,
                        inner,
                        status: KeyStatus::Secondary,
                    }),
                );
            Ok(())
        }
        pub fn primary_key_id(&self) -> u32 {
            self.primary_key_id
        }
    }
    pub(super) enum RustCryptoOutput {
        #[cfg(feature = "hmac_sha2")]
        Sha224(crate::mac::HmacSha224InternalTag),
        #[cfg(feature = "hmac_sha2")]
        Sha512_224(crate::mac::HmacSha512_224InternalTag),
        #[cfg(feature = "hmac_sha2")]
        Sha512_256(crate::mac::HmacSha512_256InternalTag),
        #[cfg(feature = "hmac_sha3")]
        Sha3_224(crate::mac::HmacSha3_224InternalTag),
        #[cfg(feature = "hmac_sha3")]
        Sha3_256(crate::mac::HmacSha3_256InternalTag),
        #[cfg(feature = "hmac_sha3")]
        Sha3_384(crate::mac::HmacSha3_384InternalTag),
        #[cfg(feature = "hmac_sha3")]
        Sha3_512(crate::mac::HmacSha3_512InternalTag),
        #[cfg(feature = "cmac_aes")]
        Aes128(crate::mac::CmacAes128InternalTag),
        #[cfg(feature = "cmac_aes")]
        Aes192(crate::mac::CmacAes192InternalTag),
        #[cfg(feature = "cmac_aes")]
        Aes256(crate::mac::CmacAes256InternalTag),
    }
    #[automatically_derived]
    impl ::core::clone::Clone for RustCryptoOutput {
        #[inline]
        fn clone(&self) -> RustCryptoOutput {
            match self {
                RustCryptoOutput::Sha224(__self_0) => {
                    RustCryptoOutput::Sha224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha512_224(__self_0) => {
                    RustCryptoOutput::Sha512_224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha512_256(__self_0) => {
                    RustCryptoOutput::Sha512_256(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha3_224(__self_0) => {
                    RustCryptoOutput::Sha3_224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha3_256(__self_0) => {
                    RustCryptoOutput::Sha3_256(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha3_384(__self_0) => {
                    RustCryptoOutput::Sha3_384(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Sha3_512(__self_0) => {
                    RustCryptoOutput::Sha3_512(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Aes128(__self_0) => {
                    RustCryptoOutput::Aes128(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Aes192(__self_0) => {
                    RustCryptoOutput::Aes192(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoOutput::Aes256(__self_0) => {
                    RustCryptoOutput::Aes256(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    impl From<RustCryptoOutput> for Output {
        fn from(output: RustCryptoOutput) -> Self {
            Self::RustCrypto(output)
        }
    }
    pub(super) struct HmacSha224InternalTag(digest::Output<hmac::Hmac<sha2::Sha224>>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha224InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha224InternalTag {
            HmacSha224InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha224InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha224>>> for HmacSha224InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha224>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha224InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha224InternalTag> for Output {
        fn from(output: HmacSha224InternalTag) -> Self {
            RustCryptoOutput::Sha224(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha224>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha224>>) -> Self {
            HmacSha224InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha512_224InternalTag(
        digest::Output<hmac::Hmac<sha2::Sha512_224>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_224InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha512_224InternalTag {
            HmacSha512_224InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha512_224InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha512_224>>>
    for HmacSha512_224InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha512_224>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha512_224InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha512_224InternalTag> for Output {
        fn from(output: HmacSha512_224InternalTag) -> Self {
            RustCryptoOutput::Sha512_224(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha512_224>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha512_224>>) -> Self {
            HmacSha512_224InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha512_256InternalTag(
        digest::Output<hmac::Hmac<sha2::Sha512_256>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_256InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha512_256InternalTag {
            HmacSha512_256InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha512_256InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha512_256>>>
    for HmacSha512_256InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha512_256>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha512_256InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha512_256InternalTag> for Output {
        fn from(output: HmacSha512_256InternalTag) -> Self {
            RustCryptoOutput::Sha512_256(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha2::Sha512_256>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha2::Sha512_256>>) -> Self {
            HmacSha512_256InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha3_224InternalTag(
        digest::Output<hmac::Hmac<sha3::Sha3_224>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_224InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha3_224InternalTag {
            HmacSha3_224InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha3_224InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_224>>> for HmacSha3_224InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_224>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha3_224InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha3_224InternalTag> for Output {
        fn from(output: HmacSha3_224InternalTag) -> Self {
            RustCryptoOutput::Sha3_224(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_224>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_224>>) -> Self {
            HmacSha3_224InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha3_256InternalTag(
        digest::Output<hmac::Hmac<sha3::Sha3_256>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_256InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha3_256InternalTag {
            HmacSha3_256InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha3_256InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_256>>> for HmacSha3_256InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_256>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha3_256InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha3_256InternalTag> for Output {
        fn from(output: HmacSha3_256InternalTag) -> Self {
            RustCryptoOutput::Sha3_256(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_256>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_256>>) -> Self {
            HmacSha3_256InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha3_384InternalTag(
        digest::Output<hmac::Hmac<sha3::Sha3_384>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_384InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha3_384InternalTag {
            HmacSha3_384InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha3_384InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_384>>> for HmacSha3_384InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_384>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha3_384InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha3_384InternalTag> for Output {
        fn from(output: HmacSha3_384InternalTag) -> Self {
            RustCryptoOutput::Sha3_384(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_384>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_384>>) -> Self {
            HmacSha3_384InternalTag::from(output).into()
        }
    }
    pub(super) struct HmacSha3_512InternalTag(
        digest::Output<hmac::Hmac<sha3::Sha3_512>>,
    );
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_512InternalTag {
        #[inline]
        fn clone(&self) -> HmacSha3_512InternalTag {
            HmacSha3_512InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for HmacSha3_512InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_512>>> for HmacSha3_512InternalTag {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_512>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for HmacSha3_512InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<HmacSha3_512InternalTag> for Output {
        fn from(output: HmacSha3_512InternalTag) -> Self {
            RustCryptoOutput::Sha3_512(output).into()
        }
    }
    impl From<digest::CtOutput<hmac::Hmac<sha3::Sha3_512>>> for Output {
        fn from(output: digest::CtOutput<hmac::Hmac<sha3::Sha3_512>>) -> Self {
            HmacSha3_512InternalTag::from(output).into()
        }
    }
    pub(super) struct CmacAes128InternalTag(digest::Output<cmac::Cmac<aes::Aes128>>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes128InternalTag {
        #[inline]
        fn clone(&self) -> CmacAes128InternalTag {
            CmacAes128InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for CmacAes128InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes128>>> for CmacAes128InternalTag {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes128>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for CmacAes128InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<CmacAes128InternalTag> for Output {
        fn from(output: CmacAes128InternalTag) -> Self {
            RustCryptoOutput::Aes128(output).into()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes128>>> for Output {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes128>>) -> Self {
            CmacAes128InternalTag::from(output).into()
        }
    }
    pub(super) struct CmacAes192InternalTag(digest::Output<cmac::Cmac<aes::Aes192>>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes192InternalTag {
        #[inline]
        fn clone(&self) -> CmacAes192InternalTag {
            CmacAes192InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for CmacAes192InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes192>>> for CmacAes192InternalTag {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes192>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for CmacAes192InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<CmacAes192InternalTag> for Output {
        fn from(output: CmacAes192InternalTag) -> Self {
            RustCryptoOutput::Aes192(output).into()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes192>>> for Output {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes192>>) -> Self {
            CmacAes192InternalTag::from(output).into()
        }
    }
    pub(super) struct CmacAes256InternalTag(digest::Output<cmac::Cmac<aes::Aes256>>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes256InternalTag {
        #[inline]
        fn clone(&self) -> CmacAes256InternalTag {
            CmacAes256InternalTag(::core::clone::Clone::clone(&self.0))
        }
    }
    impl AsRef<[u8]> for CmacAes256InternalTag {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes256>>> for CmacAes256InternalTag {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes256>>) -> Self {
            Self(output.into_bytes())
        }
    }
    impl DigestOutput for CmacAes256InternalTag {
        fn truncatable(&self) -> bool {
            true
        }
    }
    impl From<CmacAes256InternalTag> for Output {
        fn from(output: CmacAes256InternalTag) -> Self {
            RustCryptoOutput::Aes256(output).into()
        }
    }
    impl From<digest::CtOutput<cmac::Cmac<aes::Aes256>>> for Output {
        fn from(output: digest::CtOutput<cmac::Cmac<aes::Aes256>>) -> Self {
            CmacAes256InternalTag::from(output).into()
        }
    }
    impl AsRef<[u8]> for RustCryptoOutput {
        fn as_ref(&self) -> &[u8] {
            match self {
                #[cfg(feature = "hmac_sha2")]
                Self::Sha224(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha2")]
                Self::Sha512_224(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha2")]
                Self::Sha512_256(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha3")]
                Self::Sha3_224(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha3")]
                Self::Sha3_256(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha3")]
                Self::Sha3_384(tag) => tag.as_ref(),
                #[cfg(feature = "hmac_sha3")]
                Self::Sha3_512(tag) => tag.as_ref(),
                #[cfg(feature = "cmac_aes")]
                Self::Aes128(tag) => tag.as_ref(),
                #[cfg(feature = "cmac_aes")]
                Self::Aes192(tag) => tag.as_ref(),
                #[cfg(feature = "cmac_aes")]
                Self::Aes256(tag) => tag.as_ref(),
            }
        }
    }
    impl crate::mac::tag::DigestOutput for RustCryptoOutput {
        fn truncatable(&self) -> bool {
            true
        }
    }
    pub(crate) enum RustCryptoContext {
        #[cfg(feature = "hmac_sha2")]
        Sha224(HmacSha224Context),
        #[cfg(feature = "hmac_sha2")]
        Sha512_224(HmacSha512_224Context),
        #[cfg(feature = "hmac_sha2")]
        Sha512_256(HmacSha512_256Context),
        #[cfg(feature = "hmac_sha3")]
        Sha3_224(HmacSha3_224Context),
        #[cfg(feature = "hmac_sha3")]
        Sha3_256(HmacSha3_256Context),
        #[cfg(feature = "hmac_sha3")]
        Sha3_384(HmacSha3_384Context),
        #[cfg(feature = "hmac_sha3")]
        Sha3_512(HmacSha3_512Context),
        #[cfg(feature = "cmac_aes")]
        Aes128(CmacAes128Context),
        #[cfg(feature = "cmac_aes")]
        Aes192(CmacAes192Context),
        #[cfg(feature = "cmac_aes")]
        Aes256(CmacAes256Context),
    }
    impl MacContext for crate::mac::RustCryptoContext {
        fn update(&mut self, data: &[u8]) {
            match self {
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha224(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha512_224(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha512_256(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_224(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_256(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_384(ctx) => ctx.update(data),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_512(ctx) => ctx.update(data),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes128(ctx) => ctx.update(data),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes192(ctx) => ctx.update(data),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes256(ctx) => ctx.update(data),
            }
        }
        fn finalize(self) -> Output {
            match self {
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha224(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha512_224(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoContext::Sha512_256(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_224(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_256(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_384(ctx) => ctx.finalize(),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoContext::Sha3_512(ctx) => ctx.finalize(),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes128(ctx) => ctx.finalize(),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes192(ctx) => ctx.finalize(),
                #[cfg(feature = "cmac_aes")]
                RustCryptoContext::Aes256(ctx) => ctx.finalize(),
            }
        }
    }
    impl From<&crate::mac::RustCryptoKey> for crate::mac::RustCryptoContext {
        fn from(key: &crate::mac::RustCryptoKey) -> Self {
            match key {
                #[cfg(feature = "hmac_sha2")]
                RustCryptoKey::Sha224(key) => Self::Sha224(key.0.clone().into()),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoKey::Sha512_224(key) => Self::Sha512_224(key.0.clone().into()),
                #[cfg(feature = "hmac_sha2")]
                RustCryptoKey::Sha512_256(key) => Self::Sha512_256(key.0.clone().into()),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoKey::Sha3_224(key) => Self::Sha3_224(key.0.clone().into()),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoKey::Sha3_256(key) => Self::Sha3_256(key.0.clone().into()),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoKey::Sha3_384(key) => Self::Sha3_384(key.0.clone().into()),
                #[cfg(feature = "hmac_sha3")]
                RustCryptoKey::Sha3_512(key) => Self::Sha3_512(key.0.clone().into()),
                #[cfg(feature = "cmac_aes")]
                RustCryptoKey::Aes128(key) => Self::Aes128(key.0.clone().into()),
                #[cfg(feature = "cmac_aes")]
                RustCryptoKey::Aes192(key) => Self::Aes192(key.0.clone().into()),
                #[cfg(feature = "cmac_aes")]
                RustCryptoKey::Aes256(key) => Self::Aes256(key.0.clone().into()),
            }
        }
    }
    pub(super) struct HmacSha224Context(hmac::Hmac<sha2::Sha224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha224Context {
        #[inline]
        fn clone(&self) -> HmacSha224Context {
            HmacSha224Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha224Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha224Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha224Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha224Context> for RustCryptoContext {
        fn from(ctx: HmacSha224Context) -> Self {
            RustCryptoContext::Sha224(ctx)
        }
    }
    impl From<hmac::Hmac<sha2::Sha224>> for HmacSha224Context {
        fn from(ctx: hmac::Hmac<sha2::Sha224>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha512_224Context(hmac::Hmac<sha2::Sha512_224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_224Context {
        #[inline]
        fn clone(&self) -> HmacSha512_224Context {
            HmacSha512_224Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha512_224Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha512_224Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha512_224Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha512_224Context> for RustCryptoContext {
        fn from(ctx: HmacSha512_224Context) -> Self {
            RustCryptoContext::Sha512_224(ctx)
        }
    }
    impl From<hmac::Hmac<sha2::Sha512_224>> for HmacSha512_224Context {
        fn from(ctx: hmac::Hmac<sha2::Sha512_224>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha512_256Context(hmac::Hmac<sha2::Sha512_256>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_256Context {
        #[inline]
        fn clone(&self) -> HmacSha512_256Context {
            HmacSha512_256Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha512_256Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha512_256Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha512_256Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha512_256Context> for RustCryptoContext {
        fn from(ctx: HmacSha512_256Context) -> Self {
            RustCryptoContext::Sha512_256(ctx)
        }
    }
    impl From<hmac::Hmac<sha2::Sha512_256>> for HmacSha512_256Context {
        fn from(ctx: hmac::Hmac<sha2::Sha512_256>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha3_224Context(hmac::Hmac<sha3::Sha3_224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_224Context {
        #[inline]
        fn clone(&self) -> HmacSha3_224Context {
            HmacSha3_224Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha3_224Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha3_224Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha3_224Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha3_224Context> for RustCryptoContext {
        fn from(ctx: HmacSha3_224Context) -> Self {
            RustCryptoContext::Sha3_224(ctx)
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_224>> for HmacSha3_224Context {
        fn from(ctx: hmac::Hmac<sha3::Sha3_224>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha3_256Context(hmac::Hmac<sha3::Sha3_256>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_256Context {
        #[inline]
        fn clone(&self) -> HmacSha3_256Context {
            HmacSha3_256Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha3_256Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha3_256Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha3_256Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha3_256Context> for RustCryptoContext {
        fn from(ctx: HmacSha3_256Context) -> Self {
            RustCryptoContext::Sha3_256(ctx)
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_256>> for HmacSha3_256Context {
        fn from(ctx: hmac::Hmac<sha3::Sha3_256>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha3_384Context(hmac::Hmac<sha3::Sha3_384>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_384Context {
        #[inline]
        fn clone(&self) -> HmacSha3_384Context {
            HmacSha3_384Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha3_384Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha3_384Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha3_384Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha3_384Context> for RustCryptoContext {
        fn from(ctx: HmacSha3_384Context) -> Self {
            RustCryptoContext::Sha3_384(ctx)
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_384>> for HmacSha3_384Context {
        fn from(ctx: hmac::Hmac<sha3::Sha3_384>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct HmacSha3_512Context(hmac::Hmac<sha3::Sha3_512>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_512Context {
        #[inline]
        fn clone(&self) -> HmacSha3_512Context {
            HmacSha3_512Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for HmacSha3_512Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "HmacSha3_512Context",
                &&self.0,
            )
        }
    }
    impl MacContext for HmacSha3_512Context {
        fn update(&mut self, data: &[u8]) {
            use hmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use hmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<HmacSha3_512Context> for RustCryptoContext {
        fn from(ctx: HmacSha3_512Context) -> Self {
            RustCryptoContext::Sha3_512(ctx)
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_512>> for HmacSha3_512Context {
        fn from(ctx: hmac::Hmac<sha3::Sha3_512>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct CmacAes128Context(cmac::Cmac<aes::Aes128>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes128Context {
        #[inline]
        fn clone(&self) -> CmacAes128Context {
            CmacAes128Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CmacAes128Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "CmacAes128Context",
                &&self.0,
            )
        }
    }
    impl MacContext for CmacAes128Context {
        fn update(&mut self, data: &[u8]) {
            use cmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use cmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<CmacAes128Context> for RustCryptoContext {
        fn from(ctx: CmacAes128Context) -> Self {
            RustCryptoContext::Aes128(ctx)
        }
    }
    impl From<cmac::Cmac<aes::Aes128>> for CmacAes128Context {
        fn from(ctx: cmac::Cmac<aes::Aes128>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct CmacAes192Context(cmac::Cmac<aes::Aes192>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes192Context {
        #[inline]
        fn clone(&self) -> CmacAes192Context {
            CmacAes192Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CmacAes192Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "CmacAes192Context",
                &&self.0,
            )
        }
    }
    impl MacContext for CmacAes192Context {
        fn update(&mut self, data: &[u8]) {
            use cmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use cmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<CmacAes192Context> for RustCryptoContext {
        fn from(ctx: CmacAes192Context) -> Self {
            RustCryptoContext::Aes192(ctx)
        }
    }
    impl From<cmac::Cmac<aes::Aes192>> for CmacAes192Context {
        fn from(ctx: cmac::Cmac<aes::Aes192>) -> Self {
            Self(ctx)
        }
    }
    pub(super) struct CmacAes256Context(cmac::Cmac<aes::Aes256>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes256Context {
        #[inline]
        fn clone(&self) -> CmacAes256Context {
            CmacAes256Context(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CmacAes256Context {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "CmacAes256Context",
                &&self.0,
            )
        }
    }
    impl MacContext for CmacAes256Context {
        fn update(&mut self, data: &[u8]) {
            use cmac::Mac;
            self.0.update(data);
        }
        fn finalize(self) -> crate::mac::Output {
            use cmac::Mac;
            self.0.finalize().into()
        }
    }
    impl From<CmacAes256Context> for RustCryptoContext {
        fn from(ctx: CmacAes256Context) -> Self {
            RustCryptoContext::Aes256(ctx)
        }
    }
    impl From<cmac::Cmac<aes::Aes256>> for CmacAes256Context {
        fn from(ctx: cmac::Cmac<aes::Aes256>) -> Self {
            Self(ctx)
        }
    }
    pub(crate) enum RustCryptoKey {
        #[cfg(feature = "hmac_sha2")]
        Sha224(HmacSha224Key),
        #[cfg(feature = "hmac_sha2")]
        Sha512_224(HmacSha512_224Key),
        #[cfg(feature = "hmac_sha2")]
        Sha512_256(HmacSha512_256Key),
        #[cfg(feature = "hmac_sha3")]
        Sha3_224(HmacSha3_224Key),
        #[cfg(feature = "hmac_sha3")]
        Sha3_256(HmacSha3_256Key),
        #[cfg(feature = "hmac_sha3")]
        Sha3_384(HmacSha3_384Key),
        #[cfg(feature = "hmac_sha3")]
        Sha3_512(HmacSha3_512Key),
        #[cfg(feature = "cmac_aes")]
        Aes128(CmacAes128Key),
        #[cfg(feature = "cmac_aes")]
        Aes192(CmacAes192Key),
        #[cfg(feature = "cmac_aes")]
        Aes256(CmacAes256Key),
    }
    #[automatically_derived]
    impl ::core::clone::Clone for RustCryptoKey {
        #[inline]
        fn clone(&self) -> RustCryptoKey {
            match self {
                RustCryptoKey::Sha224(__self_0) => {
                    RustCryptoKey::Sha224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha512_224(__self_0) => {
                    RustCryptoKey::Sha512_224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha512_256(__self_0) => {
                    RustCryptoKey::Sha512_256(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha3_224(__self_0) => {
                    RustCryptoKey::Sha3_224(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha3_256(__self_0) => {
                    RustCryptoKey::Sha3_256(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha3_384(__self_0) => {
                    RustCryptoKey::Sha3_384(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Sha3_512(__self_0) => {
                    RustCryptoKey::Sha3_512(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Aes128(__self_0) => {
                    RustCryptoKey::Aes128(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Aes192(__self_0) => {
                    RustCryptoKey::Aes192(::core::clone::Clone::clone(__self_0))
                }
                RustCryptoKey::Aes256(__self_0) => {
                    RustCryptoKey::Aes256(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    impl From<RustCryptoKey> for MacKey {
        fn from(key: RustCryptoKey) -> Self {
            Self::RustCrypto(Box::new(key))
        }
    }
    impl RustCryptoKey {
        pub(super) fn new(
            algorithm: Algorithm,
            bytes: &[u8],
        ) -> Result<Self, crate::error::InvalidKeyLength> {
            use crate::mac::Algorithm::*;
            Ok(
                match algorithm {
                    #[cfg(feature = "hmac_sha2")]
                    Sha224 => Self::Sha224(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha2")]
                    Sha512_224 => Self::Sha512_224(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha2")]
                    Sha512_256 => Self::Sha512_256(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha3")]
                    Sha3_224 => Self::Sha3_224(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha3")]
                    Sha3_256 => Self::Sha3_256(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha3")]
                    Sha3_384 => Self::Sha3_384(bytes.try_into()?),
                    #[cfg(feature = "hmac_sha3")]
                    Sha3_512 => Self::Sha3_512(bytes.try_into()?),
                    #[cfg(feature = "cmac_aes")]
                    Aes128 => Self::Aes128(bytes.try_into()?),
                    #[cfg(feature = "cmac_aes")]
                    Aes192 => Self::Aes192(bytes.try_into()?),
                    #[cfg(feature = "cmac_aes")]
                    Aes256 => Self::Aes256(bytes.try_into()?),
                    _ => {
                        ::core::panicking::panic(
                            "internal error: entered unreachable code",
                        )
                    }
                },
            )
        }
    }
    pub(super) struct HmacSha224Key(hmac::Hmac<sha2::Sha224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha224Key {
        #[inline]
        fn clone(&self) -> HmacSha224Key {
            HmacSha224Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha2::Sha224>> for HmacSha224Key {
        fn from(key: hmac::Hmac<sha2::Sha224>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha224Key> for RustCryptoKey {
        fn from(key: HmacSha224Key) -> Self {
            Self::Sha224(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha224Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha512_224Key(hmac::Hmac<sha2::Sha512_224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_224Key {
        #[inline]
        fn clone(&self) -> HmacSha512_224Key {
            HmacSha512_224Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha2::Sha512_224>> for HmacSha512_224Key {
        fn from(key: hmac::Hmac<sha2::Sha512_224>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha512_224Key> for RustCryptoKey {
        fn from(key: HmacSha512_224Key) -> Self {
            Self::Sha512_224(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha512_224Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha512_256Key(hmac::Hmac<sha2::Sha512_256>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha512_256Key {
        #[inline]
        fn clone(&self) -> HmacSha512_256Key {
            HmacSha512_256Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha2::Sha512_256>> for HmacSha512_256Key {
        fn from(key: hmac::Hmac<sha2::Sha512_256>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha512_256Key> for RustCryptoKey {
        fn from(key: HmacSha512_256Key) -> Self {
            Self::Sha512_256(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha512_256Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha3_224Key(hmac::Hmac<sha3::Sha3_224>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_224Key {
        #[inline]
        fn clone(&self) -> HmacSha3_224Key {
            HmacSha3_224Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_224>> for HmacSha3_224Key {
        fn from(key: hmac::Hmac<sha3::Sha3_224>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha3_224Key> for RustCryptoKey {
        fn from(key: HmacSha3_224Key) -> Self {
            Self::Sha3_224(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha3_224Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha3_256Key(hmac::Hmac<sha3::Sha3_256>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_256Key {
        #[inline]
        fn clone(&self) -> HmacSha3_256Key {
            HmacSha3_256Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_256>> for HmacSha3_256Key {
        fn from(key: hmac::Hmac<sha3::Sha3_256>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha3_256Key> for RustCryptoKey {
        fn from(key: HmacSha3_256Key) -> Self {
            Self::Sha3_256(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha3_256Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha3_384Key(hmac::Hmac<sha3::Sha3_384>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_384Key {
        #[inline]
        fn clone(&self) -> HmacSha3_384Key {
            HmacSha3_384Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_384>> for HmacSha3_384Key {
        fn from(key: hmac::Hmac<sha3::Sha3_384>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha3_384Key> for RustCryptoKey {
        fn from(key: HmacSha3_384Key) -> Self {
            Self::Sha3_384(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha3_384Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct HmacSha3_512Key(hmac::Hmac<sha3::Sha3_512>);
    #[automatically_derived]
    impl ::core::clone::Clone for HmacSha3_512Key {
        #[inline]
        fn clone(&self) -> HmacSha3_512Key {
            HmacSha3_512Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<hmac::Hmac<sha3::Sha3_512>> for HmacSha3_512Key {
        fn from(key: hmac::Hmac<sha3::Sha3_512>) -> Self {
            Self(key)
        }
    }
    impl From<HmacSha3_512Key> for RustCryptoKey {
        fn from(key: HmacSha3_512Key) -> Self {
            Self::Sha3_512(key)
        }
    }
    impl TryFrom<&[u8]> for HmacSha3_512Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use hmac::Mac;
            Ok(Self(hmac::Hmac::new_from_slice(key)?))
        }
    }
    pub(super) struct CmacAes128Key(cmac::Cmac<aes::Aes128>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes128Key {
        #[inline]
        fn clone(&self) -> CmacAes128Key {
            CmacAes128Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<cmac::Cmac<aes::Aes128>> for CmacAes128Key {
        fn from(key: cmac::Cmac<aes::Aes128>) -> Self {
            Self(key)
        }
    }
    impl From<CmacAes128Key> for RustCryptoKey {
        fn from(key: CmacAes128Key) -> Self {
            Self::Aes128(key)
        }
    }
    impl TryFrom<&[u8]> for CmacAes128Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use cmac::Mac;
            Ok(Self(cmac::Cmac::new_from_slice(key)?))
        }
    }
    pub(super) struct CmacAes192Key(cmac::Cmac<aes::Aes192>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes192Key {
        #[inline]
        fn clone(&self) -> CmacAes192Key {
            CmacAes192Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<cmac::Cmac<aes::Aes192>> for CmacAes192Key {
        fn from(key: cmac::Cmac<aes::Aes192>) -> Self {
            Self(key)
        }
    }
    impl From<CmacAes192Key> for RustCryptoKey {
        fn from(key: CmacAes192Key) -> Self {
            Self::Aes192(key)
        }
    }
    impl TryFrom<&[u8]> for CmacAes192Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use cmac::Mac;
            Ok(Self(cmac::Cmac::new_from_slice(key)?))
        }
    }
    pub(super) struct CmacAes256Key(cmac::Cmac<aes::Aes256>);
    #[automatically_derived]
    impl ::core::clone::Clone for CmacAes256Key {
        #[inline]
        fn clone(&self) -> CmacAes256Key {
            CmacAes256Key(::core::clone::Clone::clone(&self.0))
        }
    }
    impl From<cmac::Cmac<aes::Aes256>> for CmacAes256Key {
        fn from(key: cmac::Cmac<aes::Aes256>) -> Self {
            Self(key)
        }
    }
    impl From<CmacAes256Key> for RustCryptoKey {
        fn from(key: CmacAes256Key) -> Self {
            Self::Aes256(key)
        }
    }
    impl TryFrom<&[u8]> for CmacAes256Key {
        type Error = crate::error::InvalidKeyLength;
        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
            use cmac::Mac;
            Ok(Self(cmac::Cmac::new_from_slice(key)?))
        }
    }
}
pub mod constant_time {
    use crate::error::UnspecifiedError;
    pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), UnspecifiedError> {
        ring_compat::ring::constant_time::verify_slices_are_equal(a, b)
            .map_err(|_| UnspecifiedError)
    }
}
pub mod hash {
    use serde::{Deserialize, Serialize};
    use crate::error::InvalidAlgorithm;
    #[serde(try_from = "u8", into = "u8")]
    pub enum Algorithm {
        Sha256 = 0,
        Sha384 = 1,
        Sha512 = 2,
        Blake3 = 3,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for Algorithm {
        #[inline]
        fn clone(&self) -> Algorithm {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for Algorithm {}
    #[automatically_derived]
    impl ::core::fmt::Debug for Algorithm {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                Algorithm::Sha256 => ::core::fmt::Formatter::write_str(f, "Sha256"),
                Algorithm::Sha384 => ::core::fmt::Formatter::write_str(f, "Sha384"),
                Algorithm::Sha512 => ::core::fmt::Formatter::write_str(f, "Sha512"),
                Algorithm::Blake3 => ::core::fmt::Formatter::write_str(f, "Blake3"),
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for Algorithm {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for Algorithm {
        #[inline]
        fn eq(&self, other: &Algorithm) -> bool {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            let __arg1_tag = ::core::intrinsics::discriminant_value(other);
            __self_tag == __arg1_tag
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for Algorithm {}
    #[automatically_derived]
    impl ::core::cmp::Eq for Algorithm {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {}
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Algorithm {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serialize::serialize(
                    &_serde::__private::Into::<
                        u8,
                    >::into(_serde::__private::Clone::clone(self)),
                    __serializer,
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Algorithm {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                _serde::__private::Result::and_then(
                    <u8 as _serde::Deserialize>::deserialize(__deserializer),
                    |v| {
                        _serde::__private::TryFrom::try_from(v)
                            .map_err(_serde::de::Error::custom)
                    },
                )
            }
        }
    };
    impl From<Algorithm> for u8 {
        fn from(algorithm: Algorithm) -> Self {
            match algorithm {
                Algorithm::Sha256 => 0,
                Algorithm::Sha384 => 1,
                Algorithm::Sha512 => 2,
                Algorithm::Blake3 => 3,
            }
        }
    }
    impl TryFrom<u8> for Algorithm {
        type Error = InvalidAlgorithm;
        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                0 => Ok(Algorithm::Sha256),
                1 => Ok(Algorithm::Sha384),
                2 => Ok(Algorithm::Sha512),
                _ => Err(InvalidAlgorithm(value)),
            }
        }
    }
}
pub mod aes {
    pub enum Aes {
        Aes128,
        Aes192,
        Aes256,
    }
}
