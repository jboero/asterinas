// SPDX-License-Identifier: MPL-2.0

use core::ops::Sub;

use super::message::{NfnlMessage, NfnlSegment};
use crate::{
    events::IoEvents,
    net::socket::{
        netlink::{
            NetlinkSocketAddr,
            common::BoundNetlink,
            message::{ContinueRead, ProtocolSegment},
        },
        util::{SendRecvFlags, datagram_common},
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

pub(super) type BoundNetlinkNetfilter = BoundNetlink<NfnlMessage>;

impl datagram_common::Bound for BoundNetlinkNetfilter {
    type Endpoint = NetlinkSocketAddr;

    fn local_endpoint(&self) -> Self::Endpoint {
        self.handle.addr()
    }

    fn bind(&mut self, endpoint: &Self::Endpoint) -> Result<()> {
        self.bind_common(endpoint)
    }

    fn remote_endpoint(&self) -> Option<&Self::Endpoint> {
        Some(&self.remote_addr)
    }

    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) {
        self.remote_addr = *endpoint;
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &Self::Endpoint,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        if *remote != NetlinkSocketAddr::new_unspecified() {
            return_errno_with_message!(
                Errno::ECONNREFUSED,
                "sending netfilter messages to user space is not supported"
            );
        }

        let sum_lens = reader.sum_lens();
        let local_port = self.handle.port();

        loop {
            let mut segment = match NfnlSegment::read_from(reader) {
                Ok(ContinueRead::Parsed(seg)) => seg,
                Ok(ContinueRead::Skipped) => continue,
                // Our `read_from` never yields an error segment; skip defensively.
                Ok(ContinueRead::SkippedErr(_)) => continue,
                Err(err) if err.error() == Errno::EFAULT => return Err(err),
                // No more valid segments to parse.
                Err(_) => break,
            };

            let header = segment.header_mut();
            if header.pid == 0 {
                header.pid = local_port;
            }

            super::kernel::handle_request(&segment, local_port);
        }

        Ok(sum_lens)
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, NetlinkSocketAddr)> {
        if !flags.sub(SendRecvFlags::MSG_PEEK).is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let mut receive_queue = self.receive_queue.lock();

        receive_queue.dequeue_if(|response, response_len| {
            let len = response_len.min(writer.sum_lens());
            response.write_to(writer)?;

            let remote = NetlinkSocketAddr::new_unspecified();
            let should_dequeue = !flags.contains(SendRecvFlags::MSG_PEEK);
            Ok((should_dequeue, (len, remote)))
        })
    }

    fn check_io_events(&self) -> IoEvents {
        self.check_io_events_common()
    }
}
