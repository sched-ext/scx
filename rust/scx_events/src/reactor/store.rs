use ::neli::socket::NlSocket;
use ::rustix_uring::{IoUring, cqueue, squeue};

use crate::reactor::buffer::BufferRing;

/// The structure that manages the Generic Netlink ACPI socket.
pub struct NetlinkGenlAcpi {
    /// The netlink socket.
    pub sock: Option<NlSocket>,
    /// The buffer ring.
    pub ring: BufferRing,
}

/// The structure that manages the Kobject Uevent Netlink socket.
pub struct NetlinkKobjectUevent {
    /// The netlink socket.
    pub sock: Option<NlSocket>,
    /// The buffer ring.
    pub ring: BufferRing,
}

/// The structure that manages storage and buffers for reactor data.
pub struct ReactorStore {
    /// The structure that manages the Generic Netlink ACPI socket.
    pub netlink_genl_acpi: NetlinkGenlAcpi,
    /// The structure that manages the Kobject Uevent Netlink socket.
    pub netlink_kobject_uevent: NetlinkKobjectUevent,
}

impl ReactorStore {
    /// Create a new [`ReactorStore`].
    pub fn new(uring: &IoUring<squeue::Entry, cqueue::Entry>) -> crate::Result<Self> {
        let netlink_genl_acpi = NetlinkGenlAcpi {
            sock: None,
            ring: BufferRing::new(uring, 0xcafe, 33, 68)?,
        };
        let netlink_kobject_uevent = NetlinkKobjectUevent {
            sock: None,
            ring: BufferRing::new(uring, 0xdead, 96, 2048)?,
        };
        Ok(Self {
            netlink_genl_acpi,
            netlink_kobject_uevent,
        })
    }
}
