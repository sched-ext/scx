use ::rapidhash::RapidInlineHashMap;
use ::winnow::BStr;

/// Kobject Uevent Netlink mcast group ID.
pub const KOBJECT_UEVENT_MCAST_GROUP: u32 = 1;

/// A Kobject Uevent Netlink message.
#[derive(Debug)]
pub struct KobjectUevent<'msg> {
    /// The kobject action.
    #[allow(dead_code, reason = "tmp")]
    pub action: KobjectUeventAction,
    /// The kobject device path.
    #[allow(dead_code, reason = "tmp")]
    pub devpath: &'msg BStr,
    /// The kobject subsystem.
    #[allow(dead_code, reason = "tmp")]
    pub subsystem: &'msg BStr,
    /// The uevent environment variables.
    #[allow(dead_code, reason = "tmp")]
    pub env: RapidInlineHashMap<&'msg BStr, &'msg BStr>,
    /// The uevent sequence number.
    #[allow(dead_code, reason = "tmp")]
    pub seq: u64,
}

/// A Kobject Uevent Netlink message header.
#[derive(Debug)]
pub struct KobjectUeventHeader<'msg> {
    /// The kobject action.
    #[allow(dead_code, reason = "tmp")]
    pub action: KobjectUeventAction,
    /// The kobject device path.
    #[allow(dead_code, reason = "tmp")]
    pub devpath: &'msg BStr,
}

// From linux/include/linux/kobject.h

/// The Kobject action.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum KobjectUeventAction {
    /// A kobject is added.
    Add,
    /// A kobject is removed.
    Remove,
    /// A kobject changed state.
    Change,
    /// A kobject changed path.
    Move,
    /// A device is online.
    Online,
    /// A device is offline.
    Offline,
    /// A device is bound to a driver.
    Bind,
    /// A device is unbound from a driver.
    Unbind,
}

/// Utility parsers for Kobject Uevent Netlink messages.
mod parsers {
    #![allow(clippy::wildcard_imports, reason = "convenience")]

    use ::winnow::{
        Parser,
        ascii::dec_uint,
        combinator::{dispatch, empty, fail, repeat_till, trace},
        error::ContextError,
        token::{take, take_until},
    };
    use winnow::BStr;

    use super::*;
    use crate::events::netlink::kobject_uevent::KobjectUevent;

    impl<'bytes> KobjectUevent<'bytes> {
        /// Entry-point to parse a Kobject Uevent message (sans-header).
        pub fn parse(stream: &mut &'bytes BStr) -> crate::Result<Self> {
            KobjectUevent::parse_body()
                .parse_next(stream)
                .map_err(crate::Error::msg)
        }

        /// Entry-point to parse a Kobject Uevent message header.
        pub fn header(stream: &mut &'bytes BStr) -> crate::Result<KobjectUeventHeader<'bytes>> {
            KobjectUeventHeader::parse_header()
                .parse_next(stream)
                .map_err(crate::Error::msg)
        }

        /// Parse a Kobject Uevent message body.
        fn parse_body() -> impl Parser<&'bytes BStr, Self, ContextError> {
            trace("uevent", move |i: &mut &'bytes BStr| {
                let action = Self::parse_key_val(b"ACTION", KobjectUeventAction::parse())
                    .parse_next(i)?
                    .1;
                let devpath = Self::parse_key_val(b"DEVPATH", Self::parse_bstr_val()).parse_next(i)?.1;
                let subsystem = Self::parse_key_val(b"SUBSYSTEM", Self::parse_bstr_val())
                    .parse_next(i)?
                    .1;
                let (env, seq) = Self::parse_env().parse_next(i)?;
                Ok(Self {
                    action,
                    devpath,
                    subsystem,
                    env,
                    seq,
                })
            })
        }

        /// Parse a Kobject Uevent message environment.
        fn parse_env() -> impl Parser<&'bytes BStr, (RapidInlineHashMap<&'bytes BStr, &'bytes BStr>, u64), ContextError>
        {
            trace(
                "env",
                repeat_till(
                    0..,
                    Self::parse_key_val(Self::parse_bstr_key(), Self::parse_bstr_val()),
                    Self::parse_key_val(b"SEQNUM", dec_uint).map(|kv| kv.1),
                ),
            )
        }

        /// Parse a key-value pair using provided parsers.
        fn parse_key_val<KO, VO, K, V>(mut keyp: K, mut valp: V) -> impl Parser<&'bytes BStr, (KO, VO), ContextError>
        where
            K: Parser<&'bytes BStr, KO, ContextError>,
            V: Parser<&'bytes BStr, VO, ContextError>,
        {
            trace("key-val", move |i: &mut &'bytes BStr| {
                let key = keyp.parse_next(i)?;
                b'='.void().parse_next(i)?;
                let val = valp.parse_next(i)?;
                b'\0'.void().parse_next(i)?;
                Ok((key, val))
            })
        }

        /// Parse a [`BStr`] key.
        fn parse_bstr_key() -> impl Parser<&'bytes BStr, &'bytes BStr, ContextError> {
            trace("key_str", take_until(0.., b'=').output_into())
        }

        /// Parse a [`BStr`] value.
        fn parse_bstr_val() -> impl Parser<&'bytes BStr, &'bytes BStr, ContextError> {
            trace("val_str", take_until(0.., b'\0').output_into())
        }
    }

    impl<'bytes> KobjectUeventHeader<'bytes> {
        /// Parse a Kobject Uevent message header.
        pub fn parse_header() -> impl Parser<&'bytes BStr, Self, ContextError> {
            trace("header", move |i: &mut &'bytes BStr| {
                let action = KobjectUeventAction::parse().parse_next(i)?;
                b"@".void().parse_next(i)?;
                let devpath = take_until(0.., b'\0').output_into().parse_next(i)?;
                b'\0'.void().parse_next(i)?;
                Ok(KobjectUeventHeader { action, devpath })
            })
        }
    }

    impl KobjectUeventAction {
        /// Parse a Kobject Uevent message action.
        pub fn parse<'bytes>() -> impl Parser<&'bytes BStr, Self, ContextError> {
            trace("action", move |i: &mut &'bytes BStr| {
                dispatch! { take::<_, &winnow::BStr, _>(3usize);
                    b"add" => empty.value(Self::Add),
                    b"rem" => b"ove".value(Self::Remove),
                    b"cha" => b"nge".value(Self::Change),
                    b"mov" => b"e".value(Self::Move),
                    b"onl" => b"ine".value(Self::Online),
                    b"off" => b"line".value(Self::Offline),
                    b"bin" => b"d".value(Self::Bind),
                    b"unb" => b"ind".value(Self::Unbind),
                    _ => fail,
                }
                .parse_next(i)
            })
        }
    }
}
