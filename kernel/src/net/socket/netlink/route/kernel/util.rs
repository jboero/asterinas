// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::{
        message::{CMsgSegHdr, DoneSegment, ProtocolSegment, SegHdrCommonFlags},
        route::message::RtnlSegment,
    },
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::AsPosixThread},
};

/// Ensures the calling thread is allowed to perform a netlink route write
/// operation (link/address creation or modification).
///
/// Linux gates these on `CAP_NET_ADMIN`; we check the current thread's effective
/// capability set, matching how socket-level privileged options are checked
/// (see `net::socket::util::options`).
///
/// Note: this checks the *caller's* effective capabilities. A stricter,
/// per-target-namespace check (`CAP_NET_ADMIN` in the owning user namespace of
/// the network namespace being modified, as Linux's `netns_capable` does) is a
/// follow-up once per-namespace netlink sockets land.
pub(super) fn require_net_admin() -> Result<()> {
    let current = current_thread!();
    let posix_thread = current
        .as_posix_thread()
        .ok_or_else(|| Error::with_message(Errno::EPERM, "not a POSIX thread"))?;

    if posix_thread
        .credentials()
        .effective_capset()
        .contains(CapSet::NET_ADMIN)
    {
        return Ok(());
    }

    return_errno_with_message!(
        Errno::EPERM,
        "netlink route write operations require CAP_NET_ADMIN"
    )
}

/// Finishes a response message.
pub fn finish_response(
    request_header: &CMsgSegHdr,
    dump_all: bool,
    response_segments: &mut Vec<RtnlSegment>,
) {
    if !dump_all {
        assert_eq!(response_segments.len(), 1);
        return;
    }
    append_done_segment(request_header, response_segments);
    add_multi_flag(response_segments);
}

/// Appends a done segment as the last segment of the provided segments.
fn append_done_segment(request_header: &CMsgSegHdr, response_segments: &mut Vec<RtnlSegment>) {
    let done_segment = DoneSegment::new_from_request(request_header, None);
    response_segments.push(RtnlSegment::Done(done_segment));
}

/// Adds the `MULTI` flag to all segments in `segments`.
fn add_multi_flag(response_segments: &mut [RtnlSegment]) {
    for segment in response_segments.iter_mut() {
        let header = segment.header_mut();
        let mut flags = SegHdrCommonFlags::from_bits_truncate(header.flags);
        flags |= SegHdrCommonFlags::MULTI;
        header.flags = flags.bits();
    }
}
