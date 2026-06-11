// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// Address-related attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/if_addr.h#L26>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum AddrAttrClass {
    UNSPEC = 0,
    ADDRESS = 1,
    LOCAL = 2,
    LABEL = 3,
    BROADCAST = 4,
    ANYCAST = 5,
    CACHEINFO = 6,
    MULTICAST = 7,
    FLAGS = 8,
    RT_PRIORITY = 9,
    TARGET_NETNSID = 10,
}

#[derive(Debug)]
pub enum AddrAttr {
    Address([u8; 4]),
    Local([u8; 4]),
    Label(CString),
}

impl AddrAttr {
    fn class(&self) -> AddrAttrClass {
        match self {
            AddrAttr::Address(_) => AddrAttrClass::ADDRESS,
            AddrAttr::Local(_) => AddrAttrClass::LOCAL,
            AddrAttr::Label(_) => AddrAttrClass::LABEL,
        }
    }
}

impl Attribute for AddrAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            AddrAttr::Address(address) => address,
            AddrAttr::Local(local) => local,
            AddrAttr::Label(label) => label.as_bytes_with_nul(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        let payload_len = header.payload_len();

        // GETADDR dump requests carry no attributes; RTM_NEWADDR requests carry
        // the address to assign (IFA_ADDRESS / IFA_LOCAL) and optionally a label.
        let Ok(class) = AddrAttrClass::try_from(header.type_()) else {
            // Unknown attributes are ignored.
            reader.skip_some(payload_len);
            return Ok(ContinueRead::Skipped);
        };

        let res = match (class, payload_len) {
            (AddrAttrClass::ADDRESS, 4) => {
                Self::Address(reader.read_val_opt::<[u8; 4]>()?.unwrap())
            }
            (AddrAttrClass::LOCAL, 4) => Self::Local(reader.read_val_opt::<[u8; 4]>()?.unwrap()),
            (AddrAttrClass::LABEL, _) => {
                let (label, consumed) = reader.read_cstring_until_end(payload_len)?;
                if consumed < payload_len {
                    reader.skip_some(payload_len - consumed);
                }
                Self::Label(label)
            }
            _ => {
                // Other (or malformed) attributes are not needed for assignment.
                reader.skip_some(payload_len);
                return Ok(ContinueRead::Skipped);
            }
        };

        Ok(ContinueRead::Parsed(res))
    }
}
