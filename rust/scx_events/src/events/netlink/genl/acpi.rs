use ::anyhow::{anyhow, bail};
use ::core::ffi::c_char;
use ::neli::{
    FromBytes as _,
    attr::{AttrHandle, Attribute as _},
    consts::{
        self,
        genl::{Cmd, NlAttrType},
    },
    err::{DeError, MsgError},
    genl::{Genlmsghdr, Nlattr},
    neli_enum,
    nl::Nlmsghdr,
    types::{Buffer, GenlBuffer},
};
use ::std::io::Cursor;
use ::winnow::{BStr, Parser as _};

// TODO(silvanshade): upstream these constants to `libc` and `neli` crates.

/// Generic Netlink ACPI command type.
#[allow(non_camel_case_types, reason = "convention")]
type acpi_genl_cmd = u8;
/// Generic Netlink ACPI attr type.
#[allow(non_camel_case_types, reason = "convention")]
type acpi_genl_attr = u16;
/// Generic Netlink ACPI event type.
#[allow(non_camel_case_types, reason = "convention")]
type acpi_genl_event = u32;

/// Generic Netlink ACPI family name.
pub const ACPI_GENL_FAMILY_NAME: &str = "acpi_event";
/// Generic Netlink ACPI version.
pub const ACPI_GENL_VERSION: u8 = 0x01;
/// Generic Netlink ACPI group name.
pub const ACPI_GENL_MCAST_GROUP_NAME: &str = "acpi_mc_group";

// From linux/drivers/acpi/event.c

/// Generic Netlink ACPI `unspecified` command.
pub const ACPI_GENL_CMD_UNSPEC: acpi_genl_cmd = 0x00;
/// Generic Netlink ACPI `event` command.
pub const ACPI_GENL_CMD_EVENT: acpi_genl_cmd = 0x01;

// From linux/drivers/acpi/event.c

/// Generic Netlink ACPI `unspecified` attr.
pub const ACPI_GENL_ATTR_UNSPEC: acpi_genl_attr = 0x00;
/// Generic Netlink ACPI `event` attr.
pub const ACPI_GENL_ATTR_EVENT: acpi_genl_attr = 0x01;

// From linux/drivers/acpi/processor_driver.c

/// Generic Netlink ACPI event type `PROCESSOR_NOTIFY_PERFORMANCE`.
pub const ACPI_PROCESSOR_NOTIFY_PERFORMANCE: acpi_genl_event = 0x80;
/// Generic Netlink ACPI event type `PROCESSOR_NOTIFY_POWER`.
pub const ACPI_PROCESSOR_NOTIFY_POWER: acpi_genl_event = 0x81;
/// Generic Netlink ACPI event type `PROCESSOR_NOTIFY_THROTTLING`.
pub const ACPI_PROCESSOR_NOTIFY_THROTTLING: acpi_genl_event = 0x82;
/// Generic Netlink ACPI event type `PROCESSOR_NOTIFY_HIGHEST_PERF_CHANGED`.
pub const ACPI_PROCESSOR_NOTIFY_HIGEST_PERF_CHANGED: acpi_genl_event = 0x85;

// From linux/include/acpi/processor.h

/// ACPI device class for processor device.
pub const ACPI_PROCESSOR_CLASS: &str = "processor";
/// ACPI device name for processor device.
pub const ACPI_PROCESSOR_DEVICE_NAME: &str = "Processor";
/// ACPI device HID for processor device.
pub const ACPI_PROCESSOR_DEVICE_HID: &str = "ACPI0007";
/// ACPI container HID for processor device.
pub const ACPI_PROCESSOR_CONTAINER_HID: &str = "ACPI0010";

// From linux/drivers/acpi/event.c

/// Generic Netlink ACPI commands.
#[neli_enum(serialized_type = "u8")]
#[non_exhaustive]
pub enum AcpiGenlCmd {
    /// Generic Netlink ACPI `unspecified` command.
    Unspec = ACPI_GENL_CMD_UNSPEC,
    /// Generic Netlink ACPI `event` command
    Event = ACPI_GENL_CMD_EVENT,
}
impl Cmd for AcpiGenlCmd {}

// From linux/drivers/acpi/event.c

/// Generic Netlink ACPI attrs.
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum AcpiGenlAttr {
    /// Generic Netlink ACPI `unspecified` attr.
    Unspec = ACPI_GENL_ATTR_UNSPEC,
    /// Generic Netlink ACPI `event` attr.
    Event = ACPI_GENL_ATTR_EVENT,
}
impl NlAttrType for AcpiGenlAttr {}

// From linux/drivers/acpi/event.c

/// A Generic Netlink ACPI Event message in raw C-str form.
///
/// See [`AcpiGenlEvent`] for the higher-level slice form.
#[derive(Debug, ::zerocopy::FromBytes, ::zerocopy::Immutable, ::zerocopy::KnownLayout)]
#[repr(C)]
pub struct AcpiGenlEventBytes {
    /// ACPI device class.
    device_class: [c_char; 20], //   20 bytes
    /// ACPI bus id.
    bus_id: [c_char; 15], // + 16 bytes = 15 + 1 (padding)
    /// ACPI event type.
    type_: acpi_genl_event, // +  4 bytes
    /// ACPI event ancillary data
    data: u32, // +  4 bytes = 44 bytes
}

// Bespoke implementation for zero-copy conversion.
impl<'msg> ::neli::FromBytesWithInputBorrowed<'msg> for &'msg AcpiGenlEventBytes {
    type Input = usize;

    #[allow(clippy::as_conversions, reason = "allow")]
    #[allow(clippy::cast_possible_truncation, reason = "allow")]
    fn from_bytes_with_input(buffer: &mut Cursor<&'msg [u8]>, input: Self::Input) -> Result<Self, DeError> {
        let len = input;
        let pos = buffer.position();
        let rem = len - pos as usize;
        let buf = buffer.get_ref();
        let buf = &buf[pos as usize..len];
        let zer = ::zerocopy::Ref::from_bytes(buf).map_err(MsgError::new)?;
        buffer.set_position(pos + len as u64);
        Ok(::zerocopy::Ref::into_ref(zer))
    }
}

// Bespoke implementation for zero-copy conversion to a safe interface.
impl<'msg> ::neli::FromBytesWithInputBorrowed<'msg> for AcpiGenlEvent<'msg> {
    type Input = usize;

    fn from_bytes_with_input(buffer: &mut Cursor<&'msg [u8]>, input: Self::Input) -> Result<Self, DeError> {
        let len = input;
        let bytes = ::neli::FromBytesWithInputBorrowed::from_bytes_with_input(buffer, input)?;
        // Perform final validation and conversion.
        <&AcpiGenlEventBytes>::try_into(bytes)
            .map_err(MsgError::new)
            .map_err(Into::into)
    }
}

/// A Generic Netlink ACPI Event message.
pub struct AcpiGenlEvent<'msg> {
    /// Underlying representation cast from message bytes.
    bytes: &'msg AcpiGenlEventBytes,
    /// ACPI device class for the event.
    device_class: &'msg BStr,
    /// ACPI device bus ID for the event.
    bus_id: &'msg BStr,
}

impl AcpiGenlEvent<'_> {
    /// The device class of the ACPI event, e.g., `"processor"`.
    #[must_use]
    pub const fn device_class(&self) -> &BStr {
        self.device_class
    }

    /// The bus id of the ACPI event, e.g., `"ACPI0007:1f"`.
    #[must_use]
    pub const fn bus_id(&self) -> &BStr {
        self.bus_id
    }

    /// The type of the ACPI event, e.g, `ACPI_PROCESSOR_NOTIFY_HIGEST_PERF_CHANGED`.
    #[must_use]
    pub const fn r#type(&self) -> u32 {
        self.bytes.type_
    }

    /// Additional data associated to the ACPI event.
    #[must_use]
    pub const fn data(&self) -> u32 {
        self.bytes.data
    }
}

impl ::core::fmt::Debug for AcpiGenlEvent<'_> {
    #[allow(clippy::host_endian_bytes, reason = "data is native-endian")]
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("AcpiGenlEvent")
            .field("device_class", &self.device_class())
            .field("bus_id", &self.bus_id())
            .field("type", &format!("{:08x?}", self.r#type()))
            .field("data", &format!("{:08x?}", self.data().to_ne_bytes()))
            .finish()
    }
}

impl<'msg> TryFrom<&'msg AcpiGenlEventBytes> for AcpiGenlEvent<'msg> {
    type Error = crate::Error;

    fn try_from(bytes: &'msg AcpiGenlEventBytes) -> crate::Result<Self> {
        use crate::data::validation::validate_cstr;
        // Validate C-string for `device_class`.
        let device_class = validate_cstr(&bytes.device_class)?;
        // Validate C-string for `bus_id`.
        let bus_id = validate_cstr(&bytes.bus_id)?;
        Ok(AcpiGenlEvent {
            bytes,
            device_class,
            bus_id,
        })
    }
}

impl<'msg> TryFrom<AcpiGenlEvent<'msg>> for AcpiProcessorNotifyHighestPerfChanged {
    type Error = crate::Error;

    fn try_from(event: AcpiGenlEvent<'msg>) -> crate::Result<Self> {
        use self::parsers::acpi_processor_notify_highest_perf_changed::bus_id_cpu;

        if event.bytes.type_ != ACPI_PROCESSOR_NOTIFY_HIGEST_PERF_CHANGED {
            bail!("event `type` mismatch");
        }
        if event.device_class() != ACPI_PROCESSOR_CLASS {
            bail!("event `device_class` mismatch");
        }
        let cpu = bus_id_cpu()
            .parse(event.bus_id())
            .map_err(|err| err.to_string())
            .map_err(crate::Error::msg)?;
        Ok(Self { cpu })
    }
}

impl TryFrom<&[u8]> for AcpiProcessorNotifyHighestPerfChanged {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        let mut cursor = ::std::io::Cursor::new(bytes);
        let msg = Nlmsghdr::<u16, Genlmsghdr<AcpiGenlCmd, AcpiGenlAttr>>::from_bytes(&mut cursor)?;
        let payload = msg.get_payload().ok_or_else(|| anyhow!("payload missing"))?;
        let handle = payload.attrs().get_attr_handle();
        let event = handle.get_attr_payload_as_with_len_borrowed(AcpiGenlAttr::Event)?;
        let bytes = <&AcpiGenlEventBytes>::try_into(event)?;
        AcpiGenlEvent::try_into(bytes)
    }
}

/// A parsed ACPI `PROCESSOR_NOTIFY_HIGEST_PERF_CHANGED` event.
#[derive(Debug)]
#[non_exhaustive]
pub struct AcpiProcessorNotifyHighestPerfChanged {
    /// The CPU of the event.
    pub cpu: u32,
}

/// Utility parsers for Generic Netlink ACPI messages.
mod parsers {
    #![allow(clippy::wildcard_imports, reason = "convenience")]

    use ::winnow::{Parser, ascii::hex_uint, error::ContextError};

    /// Utility parsers for `ACPI_PROCESSOR_NOTIFY_HIGHEST_PERF_CHANGED` events.
    pub mod acpi_processor_notify_highest_perf_changed {
        use super::*;
        use crate::events::netlink::genl::acpi::ACPI_PROCESSOR_DEVICE_HID;

        /// Utility parser for extracting the CPU from the ACPI device HID bus ID.
        pub fn bus_id_cpu<'msg>() -> impl Parser<&'msg winnow::BStr, u32, ContextError> {
            move |i: &mut &'msg winnow::BStr| {
                ACPI_PROCESSOR_DEVICE_HID.void().parse_next(i)?;
                ':'.void().parse_next(i)?;
                let cpu = hex_uint(i)?;
                Ok(cpu)
            }
        }
    }
}
