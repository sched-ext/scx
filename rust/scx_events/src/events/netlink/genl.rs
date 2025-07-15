#![allow(unused, reason = "tmp")]

use ::core::marker::PhantomData;
use ::neli::{
    attr::AttrHandle,
    consts::{
        self,
        genl::{Cmd, NlAttrType},
    },
    genl::Nlattr,
    types::{Buffer, GenlBuffer},
};

/// Definitions related to Generic Netlink ACPI messaging.
pub mod acpi;
